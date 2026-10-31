# SPDX-License-Identifier: AGPL-3.0-only
"""The pages the gateway shows itself: the entry form, the warning page and error pages."""

from __future__ import annotations

import html
from urllib.parse import urlsplit

from onionglass.reports import CATEGORIES

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
    "busy": (
        429,
        "Too many requests",
        "The gateway is busy with other requests. Try again in a moment.",
    ),
    "session_limit": (
        429,
        "Too many sites",
        "This session has opened as many different onion sites as it is allowed. Start again.",
    ),
    "quota_exhausted": (
        429,
        "Daily allowance used",
        "This account has used its allowance for today. It starts again at midnight UTC.",
    ),
    "quota_unavailable": (
        503,
        "Cannot check your allowance",
        "The service could not check this account's allowance, so it did not carry out the "
        "request. Try again later.",
    ),
    "unknown_profile": (
        403,
        "Account not set up",
        "Your account's profile is not available on this service.",
    ),
    "not_permitted": (
        403,
        "Not allowed for your account",
        "Your profile does not allow that.",
    ),
    "slow_down": (
        429,
        "Slow down",
        "Your account is making requests too quickly. Wait a moment and try again.",
    ),
    "denied": (
        403,
        "Not available here",
        "This service does not open that address.",
    ),
    "paused": (
        503,
        "Paused",
        "This service is paused. Try again later.",
    ),
    "policy_unavailable": (
        503,
        "Could not check this address",
        "The service could not check whether this address may be opened, so it did not open it. "
        "Try again later.",
    ),
    "audit_unavailable": (
        503,
        "Cannot record this request",
        "The service could not record this request, so it did not carry it out. Try again later.",
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


def landing_page(
    *, notice: str | None = None, can_open: bool = True, abuse_link: bool = False
) -> bytes:
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
    if abuse_link:
        body += '<p><a href="/abuse">Report a site or send a complaint</a></p>'
    return _page("onionglass", body)


def confirm_sign_in_page(token: str) -> bytes:
    """What a sign-in link shows. The visitor must press the button, so a page that sent them
    here cannot sign them in without their knowing. ``token`` is the link's own ticket."""
    body = (
        "<h1>Sign in</h1>"
        "<p>You followed a sign-in link. If you were expecting one, continue. If a page you "
        "were reading sent you here, do not.</p>"
        '<form method="post" action="/enter">'
        f'<input type="hidden" name="t" value="{html.escape(token)}">'
        '<button type="submit">Continue</button></form>'
        '<p><a href="/">Cancel</a></p>'
    )
    return _page("Sign in", body)


def lookalike_page(typed: str, shown: str, real_name: str, real_address: str) -> bytes:
    """The warning before an address that starts like a well-known one.

    ``typed`` is what the visitor entered, to be sent again if they go on. ``shown`` is the address
    in it. Both addresses are text, never links, so nothing here can be followed by accident.
    """
    body = (
        "<h1>This is not the site you may mean</h1>"
        f'<p class="error">The address you entered starts like the address of '
        f"{html.escape(real_name)}, but it is a different site.</p>"
        f"<p>You entered:</p><p><code>{html.escape(shown)}</code></p>"
        f"<p>{html.escape(real_name)} is at:</p><p><code>{html.escape(real_address)}</code></p>"
        "<p>Copycat sites are made on purpose to look like the real one. Check where the address "
        "came from before you go on.</p>"
        '<form method="post" action="/open">'
        f'<input type="hidden" name="address" value="{html.escape(typed)}">'
        '<input type="hidden" name="confirm" value="1">'
        '<button type="submit">Open it anyway</button></form>'
        '<p><a href="/">Go back</a></p>'
    )
    return _page("Check this address", body)


def abuse_page(contact: str | None) -> bytes:
    """How to report a site or complain, and what the operator does with it."""
    if contact is None:
        where = "<p>This operator has not published a contact for reports and complaints.</p>"
    else:
        shown = html.escape(contact)
        link = f"mailto:{contact}" if not contact.startswith("https://") else contact
        where = f'<p>Send reports and complaints to <a href="{html.escape(link)}">{shown}</a>.</p>'
    reasons = "".join(f"<li>{html.escape(label)}</li>" for label in REPORT_LABELS.values())
    body = (
        "<h1>Reports and complaints</h1>"
        f"{where}"
        "<h2>Send the address, not the material</h2>"
        "<p>Say which onion address you mean and why. Do not send the material itself, and do "
        "not attach images, files or screenshots of it. The operator does not need them, and "
        "passing them on can be a crime in some places.</p>"
        "<h2>Reporting while you browse</h2>"
        "<p>When you are looking at a site, the report button above it sends the address with "
        "one reason from this list. Nothing from the page is sent.</p>"
        f"<ul>{reasons}</ul>"
        "<h2>What happens next</h2>"
        "<p>A site that has been reported, or whose title names something the operator forbids, "
        "can be held, which stops everyone from opening it until a person has looked. The "
        "operator reports illegal material to the authority that handles it, and keeps no "
        "copy of it.</p>"
    )
    return _page("Reports and complaints", body)


VIEWER_SCRIPT = """(function () {
  "use strict";
  var frame = document.getElementById("frame");
  var address = document.getElementById("address");
  var current = "";
  var frameUrl = frame.getAttribute("src");
  var redirectBox = document.getElementById("redirect");
  var redirectGo = document.getElementById("redirect-go");
  var redirectTarget = "";
  var redirectDone = "";
  var entitiesBox = document.getElementById("entities");
  var entitiesList = document.getElementById("entities-list");
  var entitiesToggle = document.getElementById("entities-toggle");
  var readerToggle = document.getElementById("reader-toggle");
  var readerOn = false;
  var translateToggle = document.getElementById("translate-toggle");
  var translateOn = false;

  function showTranslate(on) {
    if (!translateToggle) { return; }
    translateOn = on;
    translateToggle.textContent = on ? "Original language" : "Translate";
    translateToggle.setAttribute("aria-pressed", on ? "true" : "false");
  }
  if (translateToggle) {
    translateToggle.addEventListener("click", function () {
      translateToggle.disabled = true;
      fetch("/_og/translate", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "on=" + (translateOn ? "0" : "1")
      })
        .then(function (response) { return response.ok ? response.json() : null; })
        .then(function (data) {
          if (data && typeof data.translate === "boolean") {
            showTranslate(data.translate);
            frame.src = frameUrl;
          }
        })
        .catch(function () {})
        .then(function () { translateToggle.disabled = false; });
    });
  }

  function showReader(on) {
    readerOn = on;
    readerToggle.textContent = on ? "Normal view" : "Reader view";
    readerToggle.setAttribute("aria-pressed", on ? "true" : "false");
  }
  readerToggle.addEventListener("click", function () {
    readerToggle.disabled = true;
    fetch("/_og/reader", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "on=" + (readerOn ? "0" : "1")
    })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (data && typeof data.reader === "boolean") {
          showReader(data.reader);
          frame.src = frameUrl;
        }
      })
      .catch(function () {})
      .then(function () { readerToggle.disabled = false; });
  });

  // Entities are shown as plain text, never as markup or links.
  function showEntities(items) {
    if (!entitiesBox) { return; }
    entitiesList.textContent = "";
    var shown = 0;
    for (var i = 0; i < items.length && shown < 100; i++) {
      var item = items[i];
      if (!item || typeof item.kind !== "string" || typeof item.value !== "string") { continue; }
      var row = document.createElement("li");
      row.textContent = item.kind + ": " + item.value;
      entitiesList.appendChild(row);
      shown++;
    }
    entitiesToggle.textContent = "Entities (" + shown + ")";
    entitiesToggle.hidden = shown === 0;
    if (shown === 0) { entitiesBox.hidden = true; }
  }
  if (entitiesToggle) {
    entitiesToggle.addEventListener("click", function () {
      entitiesBox.hidden = !entitiesBox.hidden;
    });
  }
  var sendButton = document.getElementById("entities-send");
  if (sendButton) {
    var sendStatus = document.getElementById("entities-send-status");
    sendButton.addEventListener("click", function () {
      sendButton.disabled = true;
      sendStatus.textContent = "Sending...";
      fetch("/_og/send-entities", { method: "POST", credentials: "same-origin" })
        .then(function (response) {
          return response.json().catch(function () { return {}; });
        })
        .then(function (data) {
          var said = data && typeof data.message === "string" ? data.message : "";
          sendStatus.textContent = said || "The entities could not be sent.";
        })
        .catch(function () { sendStatus.textContent = "The entities could not be sent."; })
        .then(function () { sendButton.disabled = false; });
    });
  }

  // Only an address on this gateway may be followed from the toolbar.
  function onThisGateway(value) {
    try {
      var url = new URL(value, window.location.href);
      return (url.protocol === "http:" || url.protocol === "https:") &&
        (url.host === window.location.host || url.host.endsWith("." + window.location.host));
    } catch (error) {
      return false;
    }
  }

  function update() {
    fetch("/_og/current", { credentials: "same-origin", cache: "no-store" })
      .then(function (response) { return response.ok ? response.json() : {}; })
      .then(function (data) {
        if (data && typeof data.reader === "boolean") { showReader(data.reader); }
        if (data && typeof data.translate === "boolean") { showTranslate(data.translate); }
        if (data && typeof data.url === "string") {
          current = data.url;
          address.textContent = data.url;
          if (typeof data.frame === "string") { frameUrl = data.frame; }
          if (Array.isArray(data.entities)) { showEntities(data.entities); }
          if (typeof data.title === "string" && data.title) {
            document.title = data.title + " - onionglass";
          }
          var asked = typeof data.refresh === "string" ? data.refresh : "";
          if (asked && asked !== redirectDone && onThisGateway(asked)) {
            redirectTarget = asked;
            redirectBox.hidden = false;
          } else {
            redirectTarget = "";
            redirectBox.hidden = true;
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
  redirectGo.addEventListener("click", function () {
    if (redirectTarget) {
      redirectDone = redirectTarget;
      redirectBox.hidden = true;
      frame.src = redirectTarget;
    }
  });
  document.getElementById("reload").addEventListener("click", function () {
    frame.src = frameUrl;
  });
  var reportButton = document.getElementById("report");
  if (reportButton) {
    var category = document.getElementById("report-category");
    var status = document.getElementById("report-status");
    reportButton.addEventListener("click", function () {
      reportButton.disabled = true;
      status.textContent = "Sending...";
      fetch("/_og/report", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "category=" + encodeURIComponent(category.value)
      })
        .then(function (response) {
          return response.json().catch(function () { return {}; });
        })
        .then(function (data) {
          status.textContent = (data && data.message) || "The report could not be sent.";
        })
        .catch(function () { status.textContent = "The report could not be sent."; })
        .then(function () { reportButton.disabled = false; });
    });
  }
  update();
  window.setInterval(update, 1500);
})();
"""

_VIEWER_STYLE = (
    "html,body{height:100%;margin:0}body{display:flex;flex-direction:column;"
    "font:14px/1.4 system-ui,sans-serif;color:#1b1b1b;background:#fafafa}"
    "#bar{padding:.4rem .7rem;border-bottom:1px solid #ccc;display:flex;flex-wrap:wrap;"
    "gap:.4rem .8rem;align-items:center}#notice{flex-basis:100%;font-size:.8rem;color:#6b4e00}"
    "[hidden]{display:none!important}"
    "#redirect{flex-basis:100%;display:flex;gap:.6rem;align-items:center;padding:.3rem .5rem;"
    "background:#fff8e1;border:1px solid #c90;border-radius:4px}"
    "#entities{flex-basis:100%;max-height:30vh;overflow:auto;border:1px solid #ccc;"
    "padding:.3rem .6rem;font:.8rem ui-monospace,monospace}#entities ul{margin:0;padding-left:1rem}"
    "#entities li{word-break:break-all}"
    "#address{flex:1;min-width:10rem;font-family:ui-monospace,monospace;word-break:break-all}"
    "button{font-size:.85rem;padding:.2rem .6rem}#frame{flex:1;width:100%;border:0;background:#fff}"
    "@media(prefers-color-scheme:dark){body{color:#eee;background:#161616}"
    "#bar{border-color:#444}#notice{color:#f0c060}a{color:#8ab4ff}}"
)


REPORT_LABELS = {
    "illegal": "Illegal content",
    "harmful": "Harmful content",
    "scam": "Scam or fraud",
    "other": "Something else",
}
REPORT_MESSAGES = {
    "received": "Thank you. The operator has your report.",
    "duplicate": "You have already reported this site.",
}


def _report_controls() -> str:
    options = "".join(
        f'<option value="{html.escape(name)}">{html.escape(REPORT_LABELS[name])}</option>'
        for name in CATEGORIES
    )
    return (
        f'<select id="report-category" aria-label="Reason for the report">{options}</select>'
        '<button id="report" type="button">Report this site</button>'
        '<output id="report-status" aria-live="polite"></output>'
    )


def viewer_page(
    frame_src: str,
    *,
    can_report: bool = False,
    can_show_entities: bool = False,
    can_send_entities: bool = False,
    can_translate: bool = False,
) -> bytes:
    """The page that frames an onion site, with the real address shown above it."""
    controls = '<button id="reader-toggle" type="button" aria-pressed="false">Reader view</button>'
    if can_translate:
        controls += (
            '<button id="translate-toggle" type="button" aria-pressed="false">Translate</button>'
        )
    if can_report:
        controls += _report_controls()
    if can_show_entities:
        controls += '<button id="entities-toggle" type="button" hidden>Entities</button>'
    send = (
        '<button id="entities-send" type="button">Send these on</button>'
        '<output id="entities-send-status" aria-live="polite"></output>'
        if can_show_entities and can_send_entities
        else ""
    )
    panel = (
        f'<div id="entities" hidden><ul id="entities-list"></ul>{send}</div>'
        if can_show_entities
        else ""
    )
    document = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>onionglass</title><style>{_VIEWER_STYLE}</style></head><body>"
        '<div id="bar"><div id="notice">'
        f"{html.escape(OPERATOR_NOTICE)}</div>"
        '<div id="redirect" hidden><span>This page asked to be sent to another address. '
        "Automatic redirects are off.</span>"
        '<button id="redirect-go" type="button">Follow it</button></div>'
        '<output id="address" aria-label="Address of the page you are viewing">Loading...</output>'
        '<button id="copy" type="button">Copy address</button>'
        '<button id="reload" type="button">Reload</button>'
        f'{controls}<a href="/">Open another address</a>{panel}</div>'
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
