#!/usr/bin/env python3
import os
import html
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote, urlparse

from kubernetes import client, config
from kubernetes.client import CustomObjectsApi

GROUP = "security.andreybondarenko.com"
VERSION = "v1alpha1"
PLURAL = "caimagereports"

REPORT_NAMESPACE = os.getenv("REPORT_NAMESPACE")
LIST_ALL_NAMESPACES = REPORT_NAMESPACE in (None, "", "all")


def load_api() -> CustomObjectsApi:
    config.load_incluster_config()
    return client.CustomObjectsApi()


def fetch_reports(api: CustomObjectsApi):
    if LIST_ALL_NAMESPACES:
        resp = api.list_cluster_custom_object(
            group=GROUP,
            version=VERSION,
            plural=PLURAL,
        )
    else:
        resp = api.list_namespaced_custom_object(
            group=GROUP,
            version=VERSION,
            plural=PLURAL,
            namespace=REPORT_NAMESPACE,
        )
    return resp.get("items", [])


def fetch_report(api: CustomObjectsApi, namespace: str, name: str):
    return api.get_namespaced_custom_object(
        group=GROUP,
        version=VERSION,
        namespace=namespace,
        plural=PLURAL,
        name=name,
    )


def html_page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      margin: 1.5rem;
      background: #0b1020;
      color: #e4e7f5;
    }}
    a {{ color: #7aa2ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    h1,h2,h3 {{ color: #ffffff; }}
    .tag {{
      display: inline-block;
      padding: 0.1rem 0.4rem;
      border-radius: 999px;
      font-size: 0.75rem;
      margin-left: 0.25rem;
    }}
    .tag-green {{ background: #1a3b2c; color: #8be9a1; border: 1px solid #3ad37a; }}
    .tag-yellow {{ background: #43381a; color: #ffd866; border: 1px solid #fbbf24; }}
    .tag-red {{ background: #4a1a1a; color: #ff6b6b; border: 1px solid #f87171; }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin-top: 1rem;
      background: #111827;
      border-radius: 0.5rem;
      overflow: hidden;
    }}
    th, td {{
      padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #1f2937;
      font-size: 0.85rem;
    }}
    th {{
      text-align: left;
      background: #020617;
      font-weight: 600;
    }}
    tr:nth-child(even) {{ background: #020617; }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 0.80rem;
    }}
    .status-pill {{
      display: inline-block;
      padding: 0.1rem 0.5rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .status-GREEN {{ background: #064e3b; color: #6ee7b7; }}
    .status-YELLOW {{ background: #78350f; color: #fde68a; }}
    .status-RED {{ background: #7f1d1d; color: #fecaca; }}
    .summary-cards {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin: 1rem 0;
    }}
    .card {{
      background: #020617;
      padding: 0.75rem 1rem;
      border-radius: 0.75rem;
      border: 1px solid #1f2937;
      min-width: 9rem;
    }}
    .card-title {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: .08em;
      color: #9ca3af;
    }}
    .card-value {{
      font-size: 1.1rem;
      font-weight: 600;
      margin-top: 0.25rem;
    }}
  </style>
</head>
<body>
{body}
</body>
</html>"""


def render_index(api: CustomObjectsApi) -> str:
    reports = fetch_reports(api)

    total_reports = len(reports)
    total_images = 0
    total_green = 0
    total_yellow = 0
    total_red = 0

    rows = []
    for item in sorted(reports, key=lambda x: (x["metadata"]["namespace"], x["metadata"]["name"])):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        name = meta.get("name", "")
        namespace = meta.get("namespace", "")
        summary = spec.get("summary", {})
        total = summary.get("totalImages", 0)
        g = summary.get("green", 0)
        y = summary.get("yellow", 0)
        r = summary.get("red", 0)

        total_images += total
        total_green += g
        total_yellow += y
        total_red += r

        status = "GREEN"
        if r > 0:
            status = "RED"
        elif y > 0:
            status = "YELLOW"

        rows.append(
            f"<tr>"
            f"<td><code>{html.escape(namespace)}</code></td>"
            f"<td><a href='/report/{html.escape(namespace)}/{html.escape(name)}'>"
            f"{html.escape(name)}</a></td>"
            f"<td><span class='status-pill status-{status}'>{status}</span></td>"
            f"<td>{total}</td><td>{g}</td><td>{y}</td><td>{r}</td>"
            f"</tr>"
        )

    body = [
        "<h1>CA Image Reports</h1>",
        "<div class='summary-cards'>",
        f"<div class='card'><div class='card-title'>Reports</div><div class='card-value'>{total_reports}</div></div>",
        f"<div class='card'><div class='card-title'>Images</div><div class='card-value'>{total_images}</div></div>",
        f"<div class='card'><div class='card-title'>Green</div><div class='card-value'>{total_green}</div></div>",
        f"<div class='card'><div class='card-title'>Yellow</div><div class='card-value'>{total_yellow}</div></div>",
        f"<div class='card'><div class='card-title'>Red</div><div class='card-value'>{total_red}</div></div>",
        "</div>",
        "<table>",
        "<thead><tr><th>Namespace</th><th>Report</th><th>Status</th><th>Total</th><th>Green</th><th>Yellow</th><th>Red</th></tr></thead>",
        "<tbody>",
        "\n".join(rows) if rows else "<tr><td colspan='7'>No CaImageReport objects found</td></tr>",
        "</tbody></table>",
    ]

    return html_page("CA Image Reports", "\n".join(body))


def render_single_report(api: CustomObjectsApi, namespace: str, name: str) -> str:
    item = fetch_report(api, namespace, name)
    spec = item.get("spec", {})
    summary = spec.get("summary", {})
    images = spec.get("report", [])

    body_parts = []
    body_parts.append(f"<h1>Report: {html.escape(name)}</h1>")
    body_parts.append(
        f"<p>Namespace: <code>{html.escape(namespace)}</code> "
        f"| <a href='/'>Back to index</a></p>"
    )

    body_parts.append("<div class='summary-cards'>")
    body_parts.append(
        f"<div class='card'><div class='card-title'>Images</div>"
        f"<div class='card-value'>{summary.get('totalImages', 0)}</div></div>"
    )
    body_parts.append(
        f"<div class='card'><div class='card-title'>Green</div>"
        f"<div class='card-value'>{summary.get('green', 0)}</div></div>"
    )
    body_parts.append(
        f"<div class='card'><div class='card-title'>Yellow</div>"
        f"<div class='card-value'>{summary.get('yellow', 0)}</div></div>"
    )
    body_parts.append(
        f"<div class='card'><div class='card-title'>Red</div>"
        f"<div class='card-value'>{summary.get('red', 0)}</div></div>"
    )
    body_parts.append("</div>")

    body_parts.append("<h2>Images</h2>")
    body_parts.append("<table>")
    body_parts.append(
        "<thead><tr><th>Image</th><th>Namespaces</th><th>Status</th><th>#Certs</th></tr></thead>"
    )
    body_parts.append("<tbody>")

    for img in images:
        image_name = img.get("image", "")
        ns_list = img.get("namespaces", [])
        status = img.get("status", "GREEN")
        certs = img.get("certs", [])

        ns_html = ", ".join(f"<code>{html.escape(n)}</code>" for n in ns_list)
        body_parts.append(
            f"<tr>"
            f"<td><code>{html.escape(image_name)}</code></td>"
            f"<td>{ns_html}</td>"
            f"<td><span class='status-pill status-{status}'>{status}</span></td>"
            f"<td>{len(certs)}</td>"
            f"</tr>"
        )

    body_parts.append("</tbody></table>")

    body_parts.append("<h2>Certificates</h2>")


    for img in images:
        image_name = img.get("image", "")
        image_status = (img.get("status") or "GREEN").upper()
        certs = img.get("certs", [])

        body_parts.append(
            f"<h3><code>{html.escape(image_name)}</code> "
            f"<span class='status-pill status-{image_status}'>{image_status}</span></h3>"
        )

        if not certs:
            body_parts.append("<p>No certificates found (treated as GREEN or empty).</p>")
            continue

        body_parts.append("<table>")
        body_parts.append(
            "<thead><tr><th>Classification</th><th>Path</th><th>Subject</th></tr></thead>"
        )
        body_parts.append("<tbody>")
        for c in certs:
            # Prefer explicit per-cert classification if it is GREEN/YELLOW/RED,
            # otherwise fall back to the image status.
            raw_cls = (c.get("classification") or "").upper()
            if raw_cls not in ("GREEN", "YELLOW", "RED"):
                raw_cls = image_status

            if raw_cls == "GREEN":
                cls_tag = "tag tag-green"
            elif raw_cls == "RED":
                cls_tag = "tag tag-red"
            else:
                cls_tag = "tag tag-yellow"

            path = c.get("path", "")
            subj = c.get("subject", "")

            body_parts.append(
                "<tr>"
                f"<td><span class='{cls_tag}'>{raw_cls}</span></td>"
                f"<td><code>{html.escape(path)}</code></td>"
                f"<td><code>{html.escape(subj)}</code></td>"
                "</tr>"
            )
        body_parts.append("</tbody></table>")

    return html_page(f"CA Image Report: {name}", "\n".join(body_parts))


class Handler(BaseHTTPRequestHandler):
    api = None

    def do_GET(self):
        try:
            if self.api is None:
                self.api = load_api()

            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                html_str = render_index(self.api)
                self._respond(200, html_str)
                return

            if path.startswith("/report/"):
                parts = path.split("/")
                if len(parts) >= 4:
                    namespace = unquote(parts[2])
                    name = unquote(parts[3])
                    html_str = render_single_report(self.api, namespace, name)
                    self._respond(200, html_str)
                    return

            self._respond(404, html_page("Not found", "<h1>404 - Not found</h1>"))
        except Exception as e:
            body = f"<h1>500 - Error</h1><pre>{html.escape(str(e))}</pre>"
            self._respond(500, html_page("Error", body))

    def _respond(self, status: int, body: str):
        enc = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(enc)))
        self.end_headers()
        self.wfile.write(enc)


def main():
    port = int(os.getenv("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(
        f"CA report UI listening on 0.0.0.0:{port}, namespace={REPORT_NAMESPACE or 'all'}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
