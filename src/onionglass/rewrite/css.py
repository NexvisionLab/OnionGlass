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


class CssTooLargeError(ValueError):
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

    def _walk(self, tokens: list[Any], *, fonts: bool, depth: int = 0) -> list[Any] | None:
        """Rebuild a token list. Returns None when the whole declaration has to be dropped."""
        if depth > MAX_DEPTH:
            return None
        result: list[Any] = []
        for token in tokens:
            if isinstance(token, ast.URLToken):
                mapped = self._map_url(token.value, fonts=fonts)
                if mapped is None:
                    return None
                result.append(self._url_block(mapped, token.source_line, token.source_column))
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
            rebuilt: list[Any] = []
            for argument in token.arguments:
                if isinstance(argument, ast.StringToken):
                    mapped = self._map_url(argument.value, fonts=False)
                    if mapped is None:
                        return None
                    rebuilt.append(
                        self._url_block(mapped, argument.source_line, argument.source_column)
                    )
                elif isinstance(argument, ast.FunctionBlock):
                    inner = self._function(argument, fonts=False, depth=depth + 1)
                    if inner is None:
                        return None
                    rebuilt.append(inner)
                else:
                    rebuilt.append(argument)
            token.arguments = rebuilt
            return token
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
        prelude = tinycss2.serialize(rule.prelude).strip()
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
            prelude = tinycss2.serialize(rule.prelude).strip()
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
    parsed = tinycss2.parse_stylesheet(css, skip_comments=True, skip_whitespace=True)
    return _escape_markup(_Sanitizer(base, mapper, options).rules(parsed))


def sanitize_declarations(
    css: str, base: OnionUrl, mapper: UrlMapper, options: CssOptions | None = None
) -> str:
    """Rebuild the value of a ``style`` attribute."""
    options = options or CssOptions()
    if len(css) > min(options.max_bytes, 20_000):
        return ""
    sanitizer = _Sanitizer(base, mapper, options)
    parts: list[str] = []
    for item in tinycss2.parse_declaration_list(css, skip_comments=True, skip_whitespace=True):
        if isinstance(item, ast.Declaration):
            piece = sanitizer.declaration(item, font_face=False)
            if piece:
                parts.append(piece)
    return _escape_markup(";".join(parts))
