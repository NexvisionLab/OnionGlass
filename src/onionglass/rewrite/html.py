# SPDX-License-Identifier: AGPL-3.0-only
"""HTML rewriting.

The page is parsed with an HTML5 parser, the same way a browser parses it, and then written out
again element by element. Nothing is copied through: every tag and attribute that appears in the
output was chosen from an allowlist by this module, and every URL was produced by
``resolve_reference``. A second allowlist pass with a different HTML implementation runs over the
result, so a mistake in one layer is caught by the other.

Properties this module is responsible for:

* P1 no script: scripts, event handlers, frames, plug-ins and vector graphics are removed
* P2 no third-party contact: every URL in the output is on the gateway
* P6 withheld images are never requested: no image URL survives unless the profile allows it
"""

from __future__ import annotations

import codecs
import html as html_lib
from dataclasses import dataclass
from urllib.parse import urljoin

import nh3
from selectolax.lexbor import LexborHTMLParser, LexborNode

from onionglass.onion import InvalidOnionError, OnionUrl, parse_onion_url
from onionglass.rewrite.css import (
    CssError,
    CssOptions,
    sanitize_declarations,
    sanitize_stylesheet,
    verify_declarations,
    verify_stylesheet,
)
from onionglass.rewrite.urls import Resolved, UrlMapper, resolve_reference

MAX_DEPTH = 400
MAX_TEXT_ATTRIBUTE = 1000
MAX_SHORT_ATTRIBUTE = 200
MAX_TITLE = 200

# Only encodings that browsers themselves decode. Python knows many more, some of which are not
# text encodings at all, and a page must not be able to pick one of those.
_BROWSER_CHARSET_PREFIXES = (
    "utf-8", "utf-16", "ascii", "latin-1", "iso8859-", "cp125", "cp874", "koi8-", "euc-",
    "gb", "big5", "shift", "cp932", "cp949", "iso2022-jp", "mac-",
)  # fmt: skip
_DROP_WITH_CONTENT = frozenset(
    {
        "script", "iframe", "frame", "frameset", "noframes", "object", "embed", "applet",
        "svg", "math", "canvas", "audio", "video", "template", "xmp", "plaintext", "dialog",
        "portal", "fencedframe", "noembed", "param", "track", "map", "area", "select-menu",
    }
)  # fmt: skip
_TRANSPARENT = frozenset({"html", "head", "body", "noscript", "picture"})
_VOID = frozenset({"br", "hr", "img", "input", "col", "wbr", "link"})
_ALLOWED_TAGS = frozenset(
    {
        "a", "abbr", "address", "article", "aside", "b", "bdi", "bdo", "blockquote", "br",
        "button", "caption", "cite", "code", "col", "colgroup", "data", "dd", "del", "details",
        "dfn", "div", "dl", "dt", "em", "fieldset", "figcaption", "figure", "footer", "form",
        "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "i", "img", "input",
        "ins", "kbd", "label", "legend", "li", "link", "main", "mark", "menu", "nav", "ol",
        "optgroup", "option", "p", "pre", "q", "rp", "rt", "ruby", "s", "samp", "section",
        "select", "small", "span", "strong", "style", "sub", "summary", "sup", "table", "tbody",
        "td", "textarea", "tfoot", "th", "thead", "time", "tr", "u", "ul", "var", "wbr",
    }
)  # fmt: skip
_GLOBAL_ATTRIBUTES = frozenset({"class", "id", "lang", "dir", "title", "hidden", "style", "role"})
_TAG_ATTRIBUTES: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "hreflang"}),
    "img": frozenset({"alt", "width", "height", "src", "srcset"}),
    "td": frozenset({"colspan", "rowspan", "headers"}),
    "th": frozenset({"colspan", "rowspan", "headers", "scope", "abbr"}),
    "col": frozenset({"span"}),
    "colgroup": frozenset({"span"}),
    "ol": frozenset({"start", "reversed", "type"}),
    "li": frozenset({"value"}),
    "time": frozenset({"datetime"}),
    "data": frozenset({"value"}),
    "del": frozenset({"datetime"}),
    "ins": frozenset({"datetime"}),
    "details": frozenset({"open"}),
    "form": frozenset({"action", "method", "enctype", "novalidate", "name"}),
    "input": frozenset(
        {
            "type",
            "name",
            "value",
            "placeholder",
            "checked",
            "disabled",
            "readonly",
            "required",
            "maxlength",
            "minlength",
            "min",
            "max",
            "step",
            "size",
            "pattern",
            "multiple",
            "accept",
            "formaction",
            "formmethod",
        }
    ),
    "button": frozenset({"type", "name", "value", "disabled", "formaction", "formmethod"}),
    "select": frozenset({"name", "multiple", "size", "disabled", "required"}),
    "option": frozenset({"value", "selected", "disabled", "label"}),
    "optgroup": frozenset({"label", "disabled"}),
    "textarea": frozenset(
        {
            "name",
            "rows",
            "cols",
            "placeholder",
            "readonly",
            "disabled",
            "required",
            "maxlength",
            "minlength",
            "wrap",
        }
    ),
    "label": frozenset({"for"}),
    "fieldset": frozenset({"disabled", "name"}),
    "link": frozenset({"rel", "href", "media", "type"}),
    "style": frozenset({"media"}),
}
_BOOLEAN_ATTRIBUTES = frozenset(
    {"hidden", "checked", "disabled", "readonly", "required", "multiple", "selected", "open",
     "reversed", "novalidate"}
)  # fmt: skip
_NUMERIC_ATTRIBUTES = frozenset(
    {"width", "height", "colspan", "rowspan", "span", "start", "size", "maxlength", "minlength",
     "rows", "cols"}
)  # fmt: skip
_SHORT_ATTRIBUTES = frozenset({"class", "id", "name", "for", "headers", "lang", "role"})
_INPUT_TYPES = frozenset(
    {"text", "search", "email", "url", "tel", "number", "password", "checkbox", "radio",
     "submit", "reset", "button", "hidden", "date", "time", "datetime-local", "month", "week",
     "color", "range", "file"}
)  # fmt: skip
_BUTTON_TYPES = frozenset({"submit", "reset", "button"})
_ENCTYPES = frozenset({"application/x-www-form-urlencoded", "multipart/form-data"})
_DIRECTIONS = frozenset({"ltr", "rtl", "auto"})
_SCOPES = frozenset({"row", "col", "rowgroup", "colgroup"})
_WRAPS = frozenset({"soft", "hard"})
_URL_ATTRIBUTES = frozenset({"href", "src", "srcset", "action", "formaction"})
_MEDIA_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ,():.-_<>=/"
)
_WITHHELD_STYLE = (
    "display:inline-block;border:1px dashed #888;padding:2px 6px;"
    "font:12px sans-serif;color:#555;background:#f4f4f4"
)
_NOTICE_STYLE = (
    "margin:0 0 12px;padding:8px 12px;border:1px solid #c90;background:#fff8e1;"
    "color:#222;font:14px sans-serif"
)

_NH3_ATTRIBUTES: dict[str, set[str]] = {
    "*": set(_GLOBAL_ATTRIBUTES),
    **{tag: set(attrs) for tag, attrs in _TAG_ATTRIBUTES.items()},
}
_NH3_ATTRIBUTES["a"] = _NH3_ATTRIBUTES["a"] | {"rel"}
_ANCHOR_REL = "noopener noreferrer nofollow"
_NH3_ATTRIBUTES["input"] = _NH3_ATTRIBUTES["input"] | {"autocomplete"}
_NH3_ATTRIBUTES["form"] = _NH3_ATTRIBUTES["form"] | {"autocomplete"}
_NH3_CLEAN_CONTENT = set(_DROP_WITH_CONTENT) | {"head", "title"}


class RewriteError(ValueError):
    """The page cannot be rewritten. The caller must refuse to serve it."""


@dataclass(frozen=True, slots=True)
class HtmlOptions:
    allow_images: bool = False
    allow_post_forms: bool = True
    allow_uploads: bool = False
    allow_password_fields: bool = True
    max_bytes: int = 5_000_000
    max_nodes: int = 200_000
    max_tags: int = 30_000
    max_output_bytes: int = 12_000_000

    @property
    def css(self) -> CssOptions:
        return CssOptions(allow_images=self.allow_images)


@dataclass(frozen=True, slots=True)
class RewriteResult:
    body: bytes
    title: str
    has_password_field: bool
    withheld_images: int
    external_links: int
    removed_scripts: int
    blocked_forms: int
    refresh_url: str | None


def decode_document(data: bytes, declared_charset: str | None = None) -> str:
    """Decode page bytes: byte order mark first, then the declared charset, then UTF-8."""
    if data.startswith(codecs.BOM_UTF8):
        return data[len(codecs.BOM_UTF8) :].decode("utf-8", errors="replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    for name in (declared_charset, _meta_charset(data)):
        if not name:
            continue
        try:
            info = codecs.lookup(name.strip().strip("\"'"))
            if info.name.startswith(_BROWSER_CHARSET_PREFIXES):
                return data.decode(info.name, errors="replace")
        except (LookupError, UnicodeError, ValueError):
            continue
    return data.decode("utf-8", errors="replace")


def _meta_charset(data: bytes) -> str | None:
    head = data[:2048].decode("ascii", errors="ignore").lower()
    position = head.find("charset=")
    if position == -1:
        return None
    rest = head[position + len("charset=") :].lstrip("\"' ")
    end = 0
    while end < len(rest) and (rest[end].isalnum() or rest[end] in "-_:."):
        end += 1
    return rest[:end] or None


def _printable(value: str, limit: int) -> str:
    cleaned = "".join(ch for ch in value if ch >= " " and ch != "\x7f")
    return cleaned[:limit]


class _Emitter:
    """Writes the sanitised document as a list of strings while walking the parsed tree."""

    def __init__(self, base: OnionUrl, mapper: UrlMapper, options: HtmlOptions) -> None:
        self.base = base
        self.mapper = mapper
        self.options = options
        self.out: list[str] = []
        self.title = ""
        self.has_password_field = False
        self.withheld_images = 0
        self.external_links = 0
        self.removed_scripts = 0
        self.blocked_forms = 0
        self.refresh_url: str | None = None
        self._nodes = 0

    # --- helpers ----------------------------------------------------------------------------

    def _resolve(self, value: str) -> Resolved:
        resolved = resolve_reference(value, self.base, self.mapper)
        if resolved.kind == "external":
            self.external_links += 1
        return resolved

    def _attr_text(self, value: str, limit: int) -> str:
        return html_lib.escape(_printable(value, limit), quote=True)

    def _emit_attribute(self, name: str, value: str) -> None:
        self.out.append(f' {name}="{html_lib.escape(value, quote=True)}"')

    # --- attributes -------------------------------------------------------------------------

    def _srcset(self, value: str) -> str:
        candidates: list[str] = []
        for part in value.split(",")[:20]:
            pieces = part.split()
            if not pieces:
                continue
            resolved = resolve_reference(pieces[0], self.base, self.mapper)
            if resolved.kind != "onion":
                continue
            descriptor = pieces[1] if len(pieces) > 1 else ""
            if descriptor and not (
                descriptor[-1] in "wx" and descriptor[:-1].replace(".", "", 1).isdigit()
            ):
                descriptor = ""
            candidates.append(f"{resolved.url} {descriptor}".strip())
        return ", ".join(candidates)

    def _attributes(self, tag: str, attributes: dict[str, str | None]) -> None:
        allowed = _TAG_ATTRIBUTES.get(tag, frozenset())
        for raw_name, raw_value in attributes.items():
            name = raw_name.lower()
            value = raw_value or ""
            if name.startswith("aria-"):
                self._emit_attribute(name, _printable(value, MAX_TEXT_ATTRIBUTE))
                continue
            if name not in _GLOBAL_ATTRIBUTES and name not in allowed:
                continue
            if name in _BOOLEAN_ATTRIBUTES:
                self._emit_attribute(name, "")
            elif name in _URL_ATTRIBUTES:
                self._url_attribute(tag, name, value)
            elif name == "style":
                css = sanitize_declarations(value, self.base, self.mapper, self.options.css)
                if css:
                    self._emit_attribute("style", css)
            elif name in _NUMERIC_ATTRIBUTES:
                if value.isascii() and value.isdigit() and len(value) <= 6:
                    self._emit_attribute(name, value)
            elif name == "dir":
                if value.lower() in _DIRECTIONS:
                    self._emit_attribute(name, value.lower())
            elif name == "scope":
                if value.lower() in _SCOPES:
                    self._emit_attribute(name, value.lower())
            elif name == "wrap":
                if value.lower() in _WRAPS:
                    self._emit_attribute(name, value.lower())
            elif name == "enctype":
                if value.lower() in _ENCTYPES:
                    self._emit_attribute(name, value.lower())
            elif name in ("method", "formmethod"):
                self._emit_attribute(name, "post" if value.lower() == "post" else "get")
            elif name == "media":
                if len(value) <= 200 and set(value) <= _MEDIA_CHARS:
                    self._emit_attribute(name, value)
            elif name in ("type", "rel"):
                continue  # written by the tag-specific code
            elif name in _SHORT_ATTRIBUTES:
                self._emit_attribute(name, _printable(value, MAX_SHORT_ATTRIBUTE))
            else:
                self._emit_attribute(name, _printable(value, MAX_TEXT_ATTRIBUTE))

    def _url_attribute(self, tag: str, name: str, value: str) -> None:
        if name == "srcset":
            if self.options.allow_images:
                mapped = self._srcset(value)
                if mapped:
                    self._emit_attribute(name, mapped)
            return
        if name == "src":
            if self.options.allow_images and tag == "img":
                resolved = resolve_reference(value, self.base, self.mapper)
                if resolved.kind == "onion":
                    self._emit_attribute(name, resolved.url)
            return
        if name == "formaction":
            # A submit target must be an onion. The warning page is for following links, and it
            # must never receive form data.
            target = resolve_reference(value, self.base, self.mapper)
            if target.kind == "onion":
                self._emit_attribute(name, target.url)
            return
        resolved = self._resolve(value)
        if resolved.kind in ("onion", "external") or (resolved.kind == "local" and resolved.url):
            self._emit_attribute(name, resolved.url)

    # --- elements ---------------------------------------------------------------------------

    def _image_placeholder(self, node: LexborNode) -> None:
        self.withheld_images += 1
        alt = _printable(node.attributes.get("alt") or "", 100) if node.tag == "img" else ""
        label = f"image withheld: {alt}" if alt else "image withheld"
        self.out.append(
            f'<span class="og-withheld" role="img" style="{_WITHHELD_STYLE}">'
            f"[{html_lib.escape(label, quote=False)}]</span>"
        )

    def _handle_meta(self, node: LexborNode) -> None:
        attributes = node.attributes
        if (attributes.get("http-equiv") or "").strip().lower() != "refresh":
            return
        content = attributes.get("content") or ""
        position = content.lower().find("url=")
        if position == -1:
            return
        target = content[position + 4 :].strip().strip("\"'")
        resolved = self._resolve(target)
        if resolved.kind in ("onion", "external"):
            self.refresh_url = resolved.url

    def _handle_link(self, node: LexborNode) -> None:
        attributes = node.attributes
        relations = (attributes.get("rel") or "").lower().split()
        if "stylesheet" not in relations or "alternate" in relations:
            return
        resolved = resolve_reference(attributes.get("href") or "", self.base, self.mapper)
        if resolved.kind != "onion":
            return
        self.out.append(
            f'<link rel="stylesheet" href="{html_lib.escape(resolved.url, quote=True)}"'
        )
        media = attributes.get("media") or ""
        if len(media) <= 200 and set(media) <= _MEDIA_CHARS and media:
            self.out.append(f' media="{html_lib.escape(media, quote=True)}"')
        self.out.append(">")

    def _handle_style(self, node: LexborNode) -> None:
        child = node.child
        text = ""
        while child is not None:
            if child.tag == "-text":
                text += child.text_content or ""
            child = child.next
        try:
            css = sanitize_stylesheet(text, self.base, self.mapper, self.options.css)
        except CssError:
            return  # a stylesheet that cannot be processed is left out, not passed on
        if not css or not verify_stylesheet(css, self.mapper):
            return
        media = node.attributes.get("media") or ""
        media_attr = ""
        if media and len(media) <= 200 and set(media) <= _MEDIA_CHARS:
            media_attr = f' media="{html_lib.escape(media, quote=True)}"'
        self.out.append(f"<style{media_attr}>{css}</style>")

    def _open_input(self, node: LexborNode) -> bool:
        attributes = node.attributes
        kind = (attributes.get("type") or "text").strip().lower()
        if kind == "image":
            kind = "submit"
        if kind not in _INPUT_TYPES:
            kind = "text"
        if kind == "file" and not self.options.allow_uploads:
            return False
        if kind == "password":
            self.has_password_field = True
            if not self.options.allow_password_fields:
                return False
        self.out.append(f'<input type="{kind}" autocomplete="off"')
        self._attributes("input", attributes)
        self.out.append(">")
        return True

    def _open_form(self, node: LexborNode) -> bool:
        """Returns False when the form must be dropped and only its contents kept."""
        attributes = node.attributes
        method = "post" if (attributes.get("method") or "").strip().lower() == "post" else "get"
        if method == "post" and not self.options.allow_post_forms:
            self.blocked_forms += 1
            return False
        action = attributes.get("action")
        action_attribute = ""
        if action is not None and action.strip():
            resolved = self._resolve(action)
            if resolved.kind != "onion" and not (resolved.kind == "local" and not resolved.url):
                self.blocked_forms += 1
                return False
            if resolved.kind == "onion":
                action_attribute = f' action="{html_lib.escape(resolved.url, quote=True)}"'
        self.out.append(f'<form method="{method}" autocomplete="off"{action_attribute}')
        remaining = {k: v for k, v in attributes.items() if k.lower() not in ("action", "method")}
        self._attributes("form", remaining)
        self.out.append(">")
        return True

    def _open_element(self, node: LexborNode) -> tuple[bool, str]:
        """Handle an opening tag. Returns (descend into children, text to write on close)."""
        tag = node.tag or ""
        if tag in _TRANSPARENT:
            return True, ""
        if tag in _DROP_WITH_CONTENT:
            if tag == "script":
                self.removed_scripts += 1
            return False, ""
        if tag == "title":
            if not self.title:
                self.title = _printable(node.text(), MAX_TITLE).strip()
            return False, ""
        if tag == "style":
            self._handle_style(node)
            return False, ""
        if tag == "link":
            self._handle_link(node)
            return False, ""
        if tag == "meta":
            self._handle_meta(node)
            return False, ""
        if tag == "base":
            return False, ""
        if tag == "img":
            if self.options.allow_images:
                self.out.append("<img")
                self._attributes("img", node.attributes)
                self.out.append(">")
            else:
                self._image_placeholder(node)
            return False, ""
        if tag == "input":
            self._open_input(node)
            return False, ""
        if tag == "form":
            return (True, "</form>") if self._open_form(node) else (True, "")
        if tag not in _ALLOWED_TAGS:
            return True, ""  # unknown element: keep its text, lose the tag
        self.out.append(f"<{tag}")
        if tag == "a":
            self.out.append(f' rel="{_ANCHOR_REL}"')
        if tag == "button":
            kind = (node.attributes.get("type") or "submit").strip().lower()
            kind = kind if kind in _BUTTON_TYPES else "submit"
            self.out.append(f' type="{kind}"')
        self._attributes(tag, node.attributes)
        self.out.append(">")
        if tag in _VOID:
            return False, ""
        return True, f"</{tag}>"

    # --- walk -------------------------------------------------------------------------------

    def walk(self, root: LexborNode) -> None:
        stack: list[tuple[LexborNode, str]] = []
        current = root.child
        while current is not None or stack:
            if current is None:
                finished, closing = stack.pop()
                if closing:
                    self.out.append(closing)
                current = finished.next
                continue
            tag = current.tag or ""
            if tag == "-text":
                text = current.text_content or ""
                parent = stack[-1][0].tag if stack else ""
                if parent in ("pre", "textarea") and text.startswith("\n"):
                    text = "\n" + text
                self.out.append(html_lib.escape(text, quote=False))
                current = current.next
                continue
            if tag.startswith("-") or tag == "!doctype":
                current = current.next
                continue
            self._nodes += 1
            if self._nodes > self.options.max_nodes:
                raise RewriteError("page has too many elements")
            descend, closing = self._open_element(current)
            if descend and current.child is not None and len(stack) < MAX_DEPTH:
                stack.append((current, closing))
                current = current.child
                continue
            if descend and closing:
                self.out.append(closing)
            current = current.next


def _final_pass(fragment: str, mapper: UrlMapper) -> str:
    """A second, independent allowlist pass over the emitted markup."""

    def attribute_filter(tag: str, attribute: str, value: str) -> str | None:
        if attribute in _URL_ATTRIBUTES:
            candidates = (
                [c.split()[0] for c in value.split(",") if c.split()]
                if attribute == "srcset"
                else [value]
            )
            if all(mapper.owns(c) for c in candidates):
                return value
            return None
        if attribute == "style":
            return value if verify_declarations(value, mapper) else None
        if tag == "input" and attribute == "type" and value not in _INPUT_TYPES:
            return None
        if attribute == "rel":
            return value if value in ("stylesheet", _ANCHOR_REL) and tag in ("a", "link") else None
        return value

    return nh3.clean(
        fragment,
        tags=set(_ALLOWED_TAGS),
        clean_content_tags=set(_NH3_CLEAN_CONTENT),
        attributes=_NH3_ATTRIBUTES,
        attribute_filter=attribute_filter,
        strip_comments=True,
        link_rel=None,
        generic_attribute_prefixes={"aria-"},
        url_schemes={"http", "https"},
    )


def _language(root: LexborNode) -> str:
    value = (root.attributes.get("lang") or "").strip()
    if 0 < len(value) <= 35 and value.isascii() and all(ch.isalnum() or ch == "-" for ch in value):
        return value
    return ""


def _rewrite_html(
    data: bytes,
    base: OnionUrl,
    mapper: UrlMapper,
    *,
    options: HtmlOptions | None = None,
    charset: str | None = None,
) -> RewriteResult:
    options = options or HtmlOptions()
    if len(data) > options.max_bytes:
        raise RewriteError("page is too large")
    text = decode_document(data, charset)
    if text.count("<") > options.max_tags:
        # Some hostile markup makes HTML parsing take quadratic time. Refuse it up front.
        raise RewriteError("page has too many tags")
    tree = LexborHTMLParser(text)
    root = tree.root
    if root is None:
        raise RewriteError("page could not be parsed")
    emitter = _Emitter(_effective_base(tree, base, mapper), mapper, options)
    emitter.walk(root)
    fragment = "".join(emitter.out)
    if len(fragment) > options.max_output_bytes:
        raise RewriteError("rewritten page is too large")
    cleaned = _final_pass(fragment, mapper)
    notice = ""
    if emitter.refresh_url:
        escaped = html_lib.escape(emitter.refresh_url, quote=True)
        notice = (
            f'<p class="og-notice" style="{_NOTICE_STYLE}">This page asked to redirect '
            f'automatically. Automatic redirects are off. <a href="{escaped}">Follow it</a>.</p>'
        )
        notice = _final_pass(notice, mapper)
    lang = _language(root)
    lang_attribute = f' lang="{html_lib.escape(lang, quote=True)}"' if lang else ""
    document = (
        "<!DOCTYPE html>"
        f"<html{lang_attribute}><head>"
        '<meta charset="utf-8">'
        '<meta name="referrer" content="no-referrer">'
        '<meta name="robots" content="noindex, nofollow">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html_lib.escape(emitter.title, quote=False)}</title>"
        f"</head><body>{notice}{cleaned}</body></html>"
    )
    return RewriteResult(
        body=document.encode("utf-8"),
        title=emitter.title,
        has_password_field=emitter.has_password_field,
        withheld_images=emitter.withheld_images,
        external_links=emitter.external_links,
        removed_scripts=emitter.removed_scripts,
        blocked_forms=emitter.blocked_forms,
        refresh_url=emitter.refresh_url,
    )


def _effective_base(tree: LexborHTMLParser, base: OnionUrl, mapper: UrlMapper) -> OnionUrl:
    """Honour a ``<base href>`` only when it stays on an onion; ignore it otherwise."""
    element = tree.css_first("base[href]")
    if element is None:
        return base
    href = (element.attributes.get("href") or "").strip()
    if not href or not href.isascii():
        return base
    try:
        return parse_onion_url(urljoin(base.url, href))
    except (InvalidOnionError, ValueError):
        return base


def rewrite_html(
    data: bytes,
    base: OnionUrl,
    mapper: UrlMapper,
    *,
    options: HtmlOptions | None = None,
    charset: str | None = None,
) -> RewriteResult:
    """Rewrite one HTML page fetched from ``base`` so the gateway can serve it.

    Raises ``RewriteError`` for any page that cannot be rewritten safely, whatever the reason.
    """
    try:
        return _rewrite_html(data, base, mapper, options=options, charset=charset)
    except RewriteError:
        raise
    except Exception as exc:  # unexpected input must end in a refusal, never a crash
        raise RewriteError("page could not be rewritten") from exc
