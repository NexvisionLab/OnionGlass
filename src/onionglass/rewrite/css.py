# SPDX-License-Identifier: AGPL-3.0-only
"""CSS sanitising and rewriting.

Stylesheets are parsed with a real CSS parser and rebuilt, never patched with text matching.
What survives:

* rules and declarations the parser understood, with every URL rewritten to the gateway
* images only when the profile allows them (property P6: withheld images are never requested)
* fonts, because a font is not an image, and imported stylesheets

What is dropped: scripting hooks (``expression()``, ``behavior``, ``-moz-binding``), anything
that fetches a resource we cannot map, unknown at-rules, and anything after a parse error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import tinycss2
from tinycss2 import ast

from onionglass.onion import OnionUrl
from onionglass.rewrite.urls import UrlMapper, resolve_reference

MAX_DEPTH = 8
_IMPORT_LIMIT = 20
_URL_FUNCTIONS = frozenset({"url", "src"})
_IMAGE_SET_FUNCTIONS = frozenset({"image-set", "-webkit-image-set"})
_BLOCKED_FUNCTIONS = frozenset(
    {
        "expression",
        "image",
        "cross-fade",
        "-webkit-cross-fade",
        "element",
        "-moz-element",
        "paint",
        "-webkit-canvas",
        "-moz-image-rect",
    }
)
_BLOCKED_PROPERTIES = frozenset({"behavior", "-ms-behavior", "-moz-binding", "-webkit-binding"})
_NESTING_AT_RULES = frozenset(
    {"media", "supports", "layer", "container", "scope", "starting-style"}
)
_KEYFRAME_AT_RULES = frozenset({"keyframes", "-webkit-keyframes", "-moz-keyframes"})
_DECLARATION_AT_RULES = frozenset({"page", "counter-style", "property"})
_NO_CONTENT = object()


class CssError(ValueError):
    """A stylesheet could not be processed. Callers drop the stylesheet."""


class CssTooLargeError(CssError):
    """The stylesheet is bigger than the configured limit."""


@dataclass(frozen=True, slots=True)
class CssOptions:
    allow_images: bool = False
    max_bytes: int = 1_000_000


def css_string(value: str) -> str:
    """A CSS string literal for ``value``."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\a ").replace("\r", "\\d ").replace("\x0c", "\\c ")
    return f'"{escaped}"'


def _escape_markup(text: str) -> str:
    """Make output safe inside an HTML style element: no angle bracket can end the element."""
    return text.replace("<", "\\3c ")


def _is_blank(token: Any) -> bool:
    return isinstance(token, ast.WhitespaceToken | ast.Comment)


def _has_variable(tokens: list[Any]) -> bool:
    return any(isinstance(t, ast.FunctionBlock) and t.lower_name == "var" for t in tokens)


def _attr_may_build_a_url(token: ast.FunctionBlock) -> bool:
    """``attr(x url)`` and ``attr(x type(<url>))`` turn an attribute's text into an address."""
    for argument in token.arguments:
        if isinstance(argument, ast.IdentToken) and argument.lower_value in ("url", "src"):
            return True
        if isinstance(argument, ast.FunctionBlock) and argument.lower_name == "type":
            return True
    return False


class _Sanitizer:
    def __init__(self, base: OnionUrl, mapper: UrlMapper, options: CssOptions) -> None:
        self._base = base
        self._mapper = mapper
        self._options = options
        self._imports = 0

    # --- references -------------------------------------------------------------------------

    def _map_url(self, value: str, *, fonts: bool) -> str | None:
        """The gateway form of a URL used as an image or font, or None if it must be dropped."""
        if value.startswith("#"):
            return value  # a reference to something inside the same document
        if not fonts and not self._options.allow_images:
            return None
        resolved = resolve_reference(value, self._base, self._mapper)
        if resolved.kind == "onion":
            return resolved.url
        return None

    def _url_block(self, value: str, line: int, column: int) -> ast.FunctionBlock:
        string = ast.StringToken(line, column, value, css_string(value))
        return ast.FunctionBlock(line, column, "url", [string])

    def _walk(
        self,
        tokens: list[Any],
        *,
        fonts: bool,
        depth: int = 0,
        strings_are_urls: bool = False,
    ) -> list[Any] | None:
        """Rebuild a token list. Returns None when the whole declaration has to be dropped.

        Every token that can name a resource is either rewritten to the gateway or causes the
        declaration to be dropped. ``strings_are_urls`` is set for the arguments of
        ``image-set()``, where a bare string is an image address.
        """
        if depth > MAX_DEPTH:
            return None
        result: list[Any] = []
        for token in tokens:
            if isinstance(token, ast.StringToken) and strings_are_urls:
                mapped = self._map_url(token.value, fonts=False)
                if mapped is None:
                    return None
                result.append(self._url_block(mapped, token.source_line, token.source_column))
            elif isinstance(token, ast.URLToken):
                mapped = self._map_url(token.value, fonts=fonts)
                if mapped is None:
                    return None
                result.append(self._url_block(mapped, token.source_line, token.source_column))
            elif isinstance(token, ast.ParseError):
                # An unterminated string or address, or a stray closing bracket. Browsers recover
                # from these in ways that are easy to get wrong, so the whole declaration goes.
                return None
            elif isinstance(token, ast.FunctionBlock):
                replacement = self._function(token, fonts=fonts, depth=depth)
                if replacement is None:
                    return None
                result.append(replacement)
            elif isinstance(
                token, ast.ParenthesesBlock | ast.SquareBracketsBlock | ast.CurlyBracketsBlock
            ):
                inner = self._walk(token.content, fonts=fonts, depth=depth + 1)
                if inner is None:
                    return None
                token.content = inner
                result.append(token)
            else:
                result.append(token)
        return result

    def _function(self, token: ast.FunctionBlock, *, fonts: bool, depth: int) -> Any | None:
        name = token.lower_name
        if name in _BLOCKED_FUNCTIONS:
            return None
        if name in _URL_FUNCTIONS:
            arguments = [a for a in token.arguments if not _is_blank(a)]
            if len(arguments) != 1 or not isinstance(arguments[0], ast.StringToken):
                return None
            mapped = self._map_url(arguments[0].value, fonts=fonts)
            if mapped is None:
                return None
            return self._url_block(mapped, token.source_line, token.source_column)
        if name in _IMAGE_SET_FUNCTIONS:
            rebuilt = self._walk(
                token.arguments, fonts=False, depth=depth + 1, strings_are_urls=True
            )
            if rebuilt is None or _has_variable(rebuilt):
                return None  # a variable could stand for an address we never saw
            token.arguments = rebuilt
            return token
        if name == "attr" and _attr_may_build_a_url(token):
            return None
        inner_tokens = self._walk(token.arguments, fonts=fonts, depth=depth + 1)
        if inner_tokens is None:
            return None
        token.arguments = inner_tokens
        return token

    # --- declarations and rules -------------------------------------------------------------

    def declaration(self, declaration: ast.Declaration, *, font_face: bool) -> str | None:
        name = declaration.lower_name
        if name in _BLOCKED_PROPERTIES:
            return None
        fonts = font_face and name == "src"
        value = self._walk(declaration.value, fonts=fonts)
        if value is None:
            return None
        declaration.value = value
        text: str = declaration.serialize()
        return text

    def _block(self, content: list[Any], depth: int, *, font_face: bool) -> str:
        parts: list[str] = []
        for item in tinycss2.parse_blocks_contents(
            content, skip_comments=True, skip_whitespace=True
        ):
            piece: str | None = None
            if isinstance(item, ast.Declaration):
                piece = self.declaration(item, font_face=font_face)
            elif isinstance(item, ast.QualifiedRule):
                piece = self._qualified(item, depth + 1)
            elif isinstance(item, ast.AtRule):
                piece = self._at_rule(item, depth + 1)
            if piece:
                parts.append(piece)
        return ";".join(parts)

    def _qualified(self, rule: ast.QualifiedRule, depth: int) -> str:
        if depth > MAX_DEPTH:
            return ""
        prelude_tokens = self._walk(rule.prelude, fonts=False)
        if prelude_tokens is None:
            return ""
        prelude = tinycss2.serialize(prelude_tokens).strip()
        if not prelude:
            return ""
        return f"{prelude}{{{self._block(rule.content, depth, font_face=False)}}}"

    def _at_rule(self, rule: ast.AtRule, depth: int) -> str:
        if depth > MAX_DEPTH:
            return ""
        keyword = rule.lower_at_keyword
        if keyword == "import":
            return self._import(rule, depth)
        if keyword == "font-face":
            if rule.content is None:
                return ""
            return f"@font-face{{{self._block(rule.content, depth, font_face=True)}}}"
        if keyword in _DECLARATION_AT_RULES:
            if rule.content is None:
                return ""
            declaration_prelude = self._walk(rule.prelude, fonts=False)
            if declaration_prelude is None:
                return ""
            prelude = tinycss2.serialize(declaration_prelude).strip()
            return f"@{keyword} {prelude}{{{self._block(rule.content, depth, font_face=False)}}}"
        if keyword in _NESTING_AT_RULES or keyword in _KEYFRAME_AT_RULES:
            prelude_tokens = self._walk(rule.prelude, fonts=False)
            if prelude_tokens is None:
                return ""
            prelude = tinycss2.serialize(prelude_tokens).strip()
            if rule.content is None:
                return f"@{keyword} {prelude};" if keyword == "layer" else ""
            inner = tinycss2.parse_rule_list(rule.content, skip_comments=True, skip_whitespace=True)
            return f"@{keyword} {prelude}{{{self.rules(inner, depth + 1)}}}"
        return ""

    def _import(self, rule: ast.AtRule, depth: int) -> str:
        if depth > 1 or self._imports >= _IMPORT_LIMIT:
            return ""
        tokens = [t for t in rule.prelude if not _is_blank(t)]
        if not tokens:
            return ""
        first, rest = tokens[0], tokens[1:]
        if isinstance(first, ast.URLToken | ast.StringToken):
            target = first.value
        elif (
            isinstance(first, ast.FunctionBlock)
            and first.lower_name == "url"
            and len([a for a in first.arguments if not _is_blank(a)]) == 1
            and isinstance(next(a for a in first.arguments if not _is_blank(a)), ast.StringToken)
        ):
            target = next(a for a in first.arguments if not _is_blank(a)).value
        else:
            return ""
        resolved = resolve_reference(target, self._base, self._mapper)
        if resolved.kind != "onion":
            return ""
        condition = self._walk(rest, fonts=False)
        if condition is None:
            return ""
        self._imports += 1
        tail = tinycss2.serialize(condition).strip()
        return f"@import url({css_string(resolved.url)}){' ' + tail if tail else ''};"

    def rules(self, rules: list[Any], depth: int = 0) -> str:
        parts: list[str] = []
        for rule in rules:
            piece = ""
            if isinstance(rule, ast.QualifiedRule):
                piece = self._qualified(rule, depth)
            elif isinstance(rule, ast.AtRule):
                piece = self._at_rule(rule, depth)
            if piece:
                parts.append(piece)
        return "\n".join(parts)


def sanitize_stylesheet(
    css: str, base: OnionUrl, mapper: UrlMapper, options: CssOptions | None = None
) -> str:
    """Rebuild a stylesheet so that it only refers to the gateway and nothing dangerous."""
    options = options or CssOptions()
    if len(css.encode("utf-8", errors="ignore")) > options.max_bytes:
        raise CssTooLargeError("stylesheet is too large")
    try:
        parsed = tinycss2.parse_stylesheet(css, skip_comments=True, skip_whitespace=True)
        return _escape_markup(_Sanitizer(base, mapper, options).rules(parsed))
    except CssError:
        raise
    except Exception as exc:  # unexpected input must end in a refusal, never a crash
        raise CssError("stylesheet could not be processed") from exc


def sanitize_declarations(
    css: str, base: OnionUrl, mapper: UrlMapper, options: CssOptions | None = None
) -> str:
    """Rebuild the value of a ``style`` attribute."""
    options = options or CssOptions()
    if len(css) > min(options.max_bytes, 20_000):
        return ""
    sanitizer = _Sanitizer(base, mapper, options)
    parts: list[str] = []
    try:
        for item in tinycss2.parse_declaration_list(css, skip_comments=True, skip_whitespace=True):
            if isinstance(item, ast.Declaration):
                piece = sanitizer.declaration(item, font_face=False)
                if piece:
                    parts.append(piece)
    except Exception:  # a style attribute that cannot be processed is dropped
        return ""
    return _escape_markup(";".join(parts))


# --- verification --------------------------------------------------------------------------------
#
# Rewriting says what the output should be. Verification looks at finished CSS and answers one
# question: could it make a browser contact anything that is not the gateway? It does not trust the
# rewriter, and it never rewrites, so running it after the rewriter cannot change what is correct.


def _owned(value: str, mapper: UrlMapper) -> bool:
    return value.startswith("#") or mapper.owns(value)


def _verify_tokens(
    tokens: list[Any], mapper: UrlMapper, *, strings_are_urls: bool = False, depth: int = 0
) -> bool:
    if depth > MAX_DEPTH:
        return False
    for token in tokens:
        if isinstance(token, ast.URLToken):
            if not _owned(token.value, mapper):
                return False
        elif isinstance(token, ast.StringToken):
            if strings_are_urls and not _owned(token.value, mapper):
                return False
        elif isinstance(token, ast.FunctionBlock):
            if not _verify_function(token, mapper, depth):
                return False
        elif isinstance(
            token, ast.ParenthesesBlock | ast.SquareBracketsBlock | ast.CurlyBracketsBlock
        ) and not _verify_tokens(token.content, mapper, depth=depth + 1):
            return False
    return True


def _verify_function(token: ast.FunctionBlock, mapper: UrlMapper, depth: int) -> bool:
    name = token.lower_name
    if name in _BLOCKED_FUNCTIONS:
        return False
    if name in _URL_FUNCTIONS:
        arguments = [a for a in token.arguments if not _is_blank(a)]
        return (
            len(arguments) == 1
            and isinstance(arguments[0], ast.StringToken)
            and _owned(arguments[0].value, mapper)
        )
    if name in _IMAGE_SET_FUNCTIONS:
        return not _has_variable(token.arguments) and _verify_tokens(
            token.arguments, mapper, strings_are_urls=True, depth=depth + 1
        )
    if name == "attr" and _attr_may_build_a_url(token):
        return False
    return _verify_tokens(token.arguments, mapper, depth=depth + 1)


def _verify_items(content: list[Any], mapper: UrlMapper, depth: int) -> bool:
    if depth > MAX_DEPTH:
        return False
    for item in tinycss2.parse_blocks_contents(content, skip_comments=True, skip_whitespace=True):
        if isinstance(item, ast.Declaration):
            if item.lower_name in _BLOCKED_PROPERTIES:
                return False
            if not _verify_tokens(item.value, mapper):
                return False
        elif isinstance(item, ast.QualifiedRule):
            if not _verify_rule(item, mapper, depth + 1):
                return False
        elif isinstance(item, ast.AtRule) and not _verify_at_rule(item, mapper, depth + 1):
            return False
    return True


def _verify_rule(rule: ast.QualifiedRule, mapper: UrlMapper, depth: int) -> bool:
    return _verify_tokens(rule.prelude, mapper) and _verify_items(rule.content, mapper, depth)


def _verify_at_rule(rule: ast.AtRule, mapper: UrlMapper, depth: int) -> bool:
    if depth > MAX_DEPTH:
        return False
    keyword = rule.lower_at_keyword
    if keyword == "import":
        tokens = [t for t in rule.prelude if not _is_blank(t)]
        first_ok = bool(tokens) and isinstance(
            tokens[0], ast.FunctionBlock | ast.StringToken | ast.URLToken
        )
        if not first_ok:
            return False
        if isinstance(tokens[0], ast.StringToken) and not _owned(tokens[0].value, mapper):
            return False
        return _verify_tokens(rule.prelude, mapper)
    known = (
        keyword == "font-face"
        or keyword in _DECLARATION_AT_RULES
        or keyword in _NESTING_AT_RULES
        or keyword in _KEYFRAME_AT_RULES
    )
    if not known or not _verify_tokens(rule.prelude, mapper):
        return False
    if rule.content is None:
        return True
    if keyword in _NESTING_AT_RULES or keyword in _KEYFRAME_AT_RULES:
        return _verify_rules(
            tinycss2.parse_rule_list(rule.content, skip_comments=True, skip_whitespace=True),
            mapper,
            depth + 1,
        )
    return _verify_items(rule.content, mapper, depth)


def _verify_rules(rules: list[Any], mapper: UrlMapper, depth: int) -> bool:
    for rule in rules:
        if isinstance(rule, ast.QualifiedRule) and not _verify_rule(rule, mapper, depth):
            return False
        if isinstance(rule, ast.AtRule) and not _verify_at_rule(rule, mapper, depth):
            return False
    return True


def verify_stylesheet(css: str, mapper: UrlMapper) -> bool:
    """True only if the stylesheet cannot make a browser contact anything but the gateway."""
    try:
        parsed = tinycss2.parse_stylesheet(css, skip_comments=True, skip_whitespace=True)
        return _verify_rules(parsed, mapper, 0)
    except Exception:  # anything unexpected counts as unverified
        return False


def verify_declarations(css: str, mapper: UrlMapper) -> bool:
    """The same check for the value of a ``style`` attribute."""
    try:
        for item in tinycss2.parse_declaration_list(css, skip_comments=True, skip_whitespace=True):
            if isinstance(item, ast.Declaration):
                if item.lower_name in _BLOCKED_PROPERTIES:
                    return False
                if not _verify_tokens(item.value, mapper):
                    return False
    except Exception:  # anything unexpected counts as unverified
        return False
    return True
