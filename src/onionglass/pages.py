# SPDX-License-Identifier: AGPL-3.0-only
"""The pages the gateway shows itself: the entry form, the warning page and error pages."""

from __future__ import annotations

import html
from urllib.parse import urlsplit

OPERATOR_NOTICE = (
    "The person running this gateway can see every address you open and everything you view "
    "through it. It does not make you anonymous. If you need that, use Tor Browser."
)

_STYLE = (
    "body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;"
    "color:#1b1b1b;background:#fafafa}h1{font-size:1.4rem}.notice{border:1px solid #c90;"
    "background:#fff8e1;padding:.6rem .9rem;border-radius:4px;font-size:.9rem}"
    "input[type=text]{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box}"
    "button{margin-top:.6rem;padding:.5rem 1rem;font-size:1rem}code{word-break:break-all}"
    ".error{border:1px solid #b00;background:#fdecec;padding:.6rem .9rem;border-radius:4px}"
    "@media(prefers-color-scheme:dark){body{color:#eee;background:#161616}"
    ".notice{background:#332a10;color:#eee}.error{background:#3a1616;color:#eee}"
    "a{color:#8ab4ff}}"
)

# kind -> (status, title, what happened)
ERRORS: dict[str, tuple[int, str, str]] = {
    "descriptor_not_found": (
        502,
        "Site not found",
        "Tor could not find this onion site. It may be offline, or the address may be wrong.",
    ),
    "descriptor_invalid": (
        502,
        "Site information is not valid",
        "Tor found the site but its published information is not valid.",
    ),
    "introduction_failed": (
        502,
        "Could not reach the site",
        "Tor found the site but could not get through to it. It may be overloaded. Try again.",
    ),
    "rendezvous_failed": (
        502,
        "Could not complete the connection",
        "Tor reached the site but could not finish connecting. Try again in a moment.",
    ),
    "introduction_timeout": (
        504,
        "The site took too long",
        "The site did not answer in time. It may be offline or overloaded.",
    ),
    "auth_required": (
        403,
        "This site needs a key",
        "This onion site is private and needs an authorisation key this gateway does not have.",
    ),
    "auth_wrong": (
        403,
        "The key was not accepted",
        "This onion site is private and rejected the authorisation key.",
    ),
    "invalid_address": (
        400,
        "Not a valid onion address",
        "That is not a valid version 3 onion address.",
    ),
    "timeout": (504, "The site took too long", "The site did not finish answering in time."),
    "connect_timeout": (
        504,
        "The site took too long",
        "Connecting to the site took too long. It may be offline or overloaded.",
    ),
    "proxy_unreachable": (
        503,
        "Tor is not available",
        "The gateway cannot reach Tor right now. This is a problem on the gateway, not the site.",
    ),
    "connection_refused": (
        502,
        "The site refused the connection",
        "The site is online but is not accepting connections on that port.",
    ),
    "connection_closed": (
        502,
        "The connection was cut",
        "The connection to the site was cut before the page was complete.",
    ),
    "too_large": (
        502,
        "The page is too large",
        "The response is bigger than this gateway will handle.",
    ),
    "tls_failed": (
        502,
        "Secure connection failed",
        "The site did not complete a secure connection. Its plain http address may still work.",
    ),
    "protocol_error": (
        502,
        "Unexpected reply from the site",
        "The site sent something that is not a valid web response.",
    ),
    "bad_response": (
        502,
        "The response could not be read",
        "The page was compressed in a way this gateway cannot read, or was damaged.",
    ),
    "rewrite_failed": (
        502,
        "The page could not be shown safely",
        "The page was too complex or too large to make safe, so it was not shown.",
    ),
    "blocked_type": (
        403,
        "This kind of file is not available",
        "This gateway does not pass on that kind of file. Pages, stylesheets and fonts are shown.",
    ),
    "images_withheld": (
        403,
        "Image withheld",
        "Images are not loaded by this gateway unless the operator turns them on.",
    ),
    "bad_redirect": (
        502,
        "The site sent you somewhere this gateway cannot follow",
        "The site asked for a redirect to an address that cannot be shown safely.",
    ),
    "bad_request": (400, "Bad request", "The request could not be understood."),
    "payload_too_large": (413, "Request too large", "The data you sent is too large."),
    "unsupported_media": (415, "Not supported", "That kind of form data is not supported."),
    "method_not_allowed": (405, "Not allowed", "That request method is not allowed."),
    "not_found": (404, "Not found", "There is nothing at this address."),
    "expired_session": (
        410,
        "Session ended",
        "This session has ended. Go back to the gateway's start page to open the site again.",
    ),
    "forbidden": (403, "Not allowed", "This address belongs to a different session."),
    "sign_in_required": (
        403,
        "Sign in first",
        "You need to sign in before you can open an address.",
    ),
    "session_limit": (
        429,
        "Too many sites",
        "This session has opened as many different onion sites as it is allowed. Start again.",
    ),
    "internal": (500, "Something went wrong", "The gateway hit an unexpected problem."),
}


def _page(title: str, body: str) -> bytes:
    document = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body>{body}</body></html>"
    )
    return document.encode("utf-8")


def error_page(kind: str) -> tuple[int, bytes]:
    status, title, message = ERRORS.get(kind, ERRORS["internal"])
    body = (
        f'<h1>{html.escape(title)}</h1><p class="error">{html.escape(message)}</p>'
        "<p>You can close this tab or go back.</p>"
    )
    return status, _page(title, body)


def landing_page(*, notice: str | None = None, can_open: bool = True) -> bytes:
    problem = f'<p class="error">{html.escape(notice)}</p>' if notice else ""
    if can_open:
        form = (
            '<form method="post" action="/open"><label for="address">Onion address</label>'
            '<input id="address" name="address" type="text" autocomplete="off" '
            'placeholder="example.onion" required maxlength="2000">'
            '<button type="submit">Open</button></form>'
        )
    else:
        form = "<p>You need to sign in before you can open an address.</p>"
    body = (
        "<h1>onionglass</h1>"
        f'<p class="notice">{html.escape(OPERATOR_NOTICE)}</p>{problem}{form}'
        "<p>Pages are shown without scripts. Images are not loaded unless the operator allows "
        "them.</p>"
    )
    return _page("onionglass", body)


VIEWER_SCRIPT = """(function () {
  "use strict";
  var frame = document.getElementById("frame");
  var address = document.getElementById("address");
  var current = "";
  var frameUrl = frame.getAttribute("src");

  function update() {
    fetch("/_og/current", { credentials: "same-origin", cache: "no-store" })
      .then(function (response) { return response.ok ? response.json() : {}; })
      .then(function (data) {
        if (data && typeof data.url === "string") {
          current = data.url;
          address.textContent = data.url;
          if (typeof data.frame === "string") { frameUrl = data.frame; }
          if (typeof data.title === "string" && data.title) {
            document.title = data.title + " - onionglass";
          }
        }
      })
      .catch(function () {});
  }

  document.getElementById("copy").addEventListener("click", function () {
    if (current && navigator.clipboard) {
      navigator.clipboard.writeText(current).catch(function () {});
    }
  });
  document.getElementById("reload").addEventListener("click", function () {
    frame.src = frameUrl;
  });
  update();
  window.setInterval(update, 1500);
})();
"""

_VIEWER_STYLE = (
    "html,body{height:100%;margin:0}body{display:flex;flex-direction:column;"
    "font:14px/1.4 system-ui,sans-serif;color:#1b1b1b;background:#fafafa}"
    "#bar{padding:.4rem .7rem;border-bottom:1px solid #ccc;display:flex;flex-wrap:wrap;"
    "gap:.4rem .8rem;align-items:center}#notice{flex-basis:100%;font-size:.8rem;color:#6b4e00}"
    "#address{flex:1;min-width:10rem;font-family:ui-monospace,monospace;word-break:break-all}"
    "button{font-size:.85rem;padding:.2rem .6rem}#frame{flex:1;width:100%;border:0;background:#fff}"
    "@media(prefers-color-scheme:dark){body{color:#eee;background:#161616}"
    "#bar{border-color:#444}#notice{color:#f0c060}a{color:#8ab4ff}}"
)


def viewer_page(frame_src: str) -> bytes:
    """The page that frames an onion site, with the real address shown above it."""
    document = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>onionglass</title><style>{_VIEWER_STYLE}</style></head><body>"
        '<div id="bar"><div id="notice">'
        f"{html.escape(OPERATOR_NOTICE)}</div>"
        '<output id="address" aria-label="Address of the page you are viewing">Loading...</output>'
        '<button id="copy" type="button">Copy address</button>'
        '<button id="reload" type="button">Reload</button>'
        '<a href="/">Open another address</a></div>'
        f'<iframe id="frame" title="Page from the onion site" src="{html.escape(frame_src)}" '
        'sandbox="allow-forms allow-same-origin allow-popups allow-popups-to-escape-sandbox" '
        'referrerpolicy="no-referrer"></iframe>'
        '<script src="/_og/viewer.js"></script></body></html>'
    )
    return document.encode("utf-8")


def blocked_page() -> bytes:
    body = (
        "<h1>Link not available</h1>"
        '<p class="error">The page you came from named more different onion sites than this '
        "gateway will open in one session, so this link was turned off.</p>"
    )
    return _page("Link not available", body)


def external_page(url: str) -> bytes:
    """The warning shown before a link that leaves Tor. ``url`` must already be validated."""
    parts = urlsplit(url)
    host = html.escape(parts.hostname or "unknown")
    shown = html.escape(url if len(url) <= 300 else url[:300] + "...")
    body = (
        "<h1>This link leaves Tor</h1>"
        '<p class="notice">If you continue, your own browser will connect directly to '
        f"<strong>{host}</strong>. That site will see your internet address, and so will "
        "anyone watching your connection. This gateway cannot protect you there.</p>"
        f"<p>Full address: <code>{shown}</code></p>"
        f'<p><a href="{html.escape(url, quote=True)}" target="_blank" '
        'rel="noopener noreferrer nofollow">Continue to the site</a></p>'
        "<p>Otherwise, close this page or go back.</p>"
    )
    return _page("This link leaves Tor", body)
