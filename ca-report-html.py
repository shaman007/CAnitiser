#!/usr/bin/env python3
import argparse
import json
import sys
import html
from collections import Counter


def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"ERROR: cannot read JSON {path}: {e}", file=sys.stderr)
        sys.exit(1)


def build_html(report):
    # report: list of entries from ca-analyse.py
    status_counter = Counter()
    ns_counter = Counter()

    for item in report:
        status = item.get("status", "UNKNOWN")
        status_counter[status] += 1
        for ns in item.get("namespaces", []):
            ns_counter[ns] += 1

    total_images = len(report)

    def esc(s: str) -> str:
        return html.escape(str(s), quote=True)

    # Build namespace summary HTML
    ns_rows = []
    for ns, count in sorted(ns_counter.items(), key=lambda kv: kv[0]):
        ns_rows.append(
            f"<tr><td>{esc(ns)}</td><td>{count}</td></tr>"
        )
    ns_table_html = (
        "<table class='ns-table'>"
        "<thead><tr><th>Namespace</th><th>Images</th></tr></thead>"
        "<tbody>"
        + "".join(ns_rows)
        + "</tbody></table>"
    )

    # Build rows for main table
    rows_html = []
    for idx, item in enumerate(report, start=1):
        image = item.get("image", "")
        status = item.get("status", "UNKNOWN")
        namespaces = item.get("namespaces", [])
        blacklist_matches = item.get("blacklist_matches", []) or []
        whitelist_matches = item.get("whitelist_matches", []) or []
        not_matched = item.get("not_matched", []) or []

        status_lower = status.lower()

        # Join namespaces
        ns_html = ", ".join(esc(ns) for ns in namespaces) if namespaces else "&mdash;"

        # Build cert details
        def cert_list_html(title, certs, css_class):
            if not certs:
                return ""
            items = []
            for c in certs:
                path = esc(c.get("path", ""))
                subject = esc(c.get("subject", ""))
                pat = esc(c.get("pattern", "")) if "pattern" in c else ""
                pat_span = f"<span class='pattern'>{pat}</span> " if pat else ""
                items.append(
                    f"<li>{pat_span}<code class='cert-path'>{path}</code><br>"
                    f"<span class='cert-subject'>{subject}</span></li>"
                )
            return (
                f"<details class='cert-block {css_class}' open>"
                f"<summary>{esc(title)} ({len(certs)})</summary>"
                f"<ul>{''.join(items)}</ul>"
                "</details>"
            )

        bl_html = cert_list_html("Blacklisted matches", blacklist_matches, "bl")
        wl_html = cert_list_html("Whitelisted matches", whitelist_matches, "wl")
        nm_html = cert_list_html("Other certificates", not_matched, "nm")

        certs_html = bl_html + wl_html + nm_html
        if not certs_html:
            certs_html = "<span class='no-certs'>&mdash;</span>"

        # for search
        search_text = " ".join(
            [
                image,
                " ".join(namespaces),
                " ".join(c.get("subject", "") for c in blacklist_matches),
                " ".join(c.get("subject", "") for c in whitelist_matches),
                " ".join(c.get("subject", "") for c in not_matched),
            ]
        )

        rows_html.append(
            f"<tr class='image-row' "
            f"data-status='{esc(status_lower)}' "
            f"data-search='{esc(search_text.lower())}'>"
            f"<td class='col-idx'>{idx}</td>"
            f"<td class='col-status'><span class='status-badge status-{esc(status_lower)}'>{esc(status)}</span></td>"
            f"<td class='col-image'><code>{esc(image)}</code></td>"
            f"<td class='col-ns'>{ns_html}</td>"
            f"<td class='col-certs'>{certs_html}</td>"
            "</tr>"
        )

    # Status summary numbers
    green_count = status_counter.get("GREEN", 0)
    yellow_count = status_counter.get("YELLOW", 0)
    red_count = status_counter.get("RED", 0)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Kubernetes CA Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --bg-alt: #020617;
      --card-bg: #020617;
      --border: #1e293b;
      --text: #e5e7eb;
      --text-muted: #9ca3af;
      --accent: #38bdf8;
      --green: #22c55e;
      --yellow: #eab308;
      --red: #ef4444;
      --mono: Menlo, Monaco, SFMono-Regular, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      padding: 0;
      font-family: var(--sans);
      background: radial-gradient(circle at top left, #1e293b 0, #020617 50%, #000 100%);
      color: var(--text);
    }}
    .page {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px 16px 40px;
    }}
    h1 {{
      font-size: 28px;
      margin-bottom: 4px;
    }}
    .subtitle {{
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 20px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }}
    .card {{
      background: linear-gradient(145deg, rgba(15,23,42,0.95), rgba(15,23,42,0.75));
      border-radius: 12px;
      border: 1px solid rgba(148,163,184,0.15);
      padding: 12px 14px;
      backdrop-filter: blur(16px);
      box-shadow: 0 18px 40px rgba(15,23,42,0.7);
    }}
    .card-title {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin-bottom: 4px;
    }}
    .card-value {{
      font-size: 22px;
      font-weight: 600;
    }}
    .card-label {{
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 2px;
    }}
    .card-status-green .card-value {{ color: var(--green); }}
    .card-status-yellow .card-value {{ color: var(--yellow); }}
    .card-status-red .card-value {{ color: var(--red); }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 12px 20px;
      margin-bottom: 16px;
      background: rgba(15,23,42,0.85);
      border-radius: 12px;
      border: 1px solid rgba(148,163,184,0.25);
      padding: 10px 14px;
    }}
    .controls-group {{
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }}
    .controls-label {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
    }}
    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.4);
      font-size: 11px;
      cursor: pointer;
      user-select: none;
      background: rgba(15,23,42,0.9);
    }}
    .chip input {{
      accent-color: var(--accent);
      cursor: pointer;
    }}
    .search-input {{
      padding: 5px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.4);
      background: rgba(15,23,42,0.9);
      color: var(--text);
      font-size: 13px;
      min-width: 220px;
    }}
    .search-input::placeholder {{
      color: #6b7280;
    }}
    .tables {{
      display: grid;
      grid-template-columns: minmax(0, 2fr) minmax(0, 1fr);
      gap: 16px;
    }}
    @media (max-width: 900px) {{
      .tables {{ grid-template-columns: minmax(0, 1fr); }}
    }}
    .main-table-wrapper {{
      background: rgba(15,23,42,0.85);
      border-radius: 12px;
      border: 1px solid rgba(148,163,184,0.3);
      overflow: hidden;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      font-size: 12px;
    }}
    thead {{
      background: rgba(15,23,42,0.96);
    }}
    th, td {{
      padding: 6px 8px;
      border-bottom: 1px solid rgba(51,65,85,0.7);
      vertical-align: top;
    }}
    th {{
      text-align: left;
      font-weight: 500;
      color: var(--text-muted);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    tbody tr:nth-child(even) {{
      background: rgba(15,23,42,0.80);
    }}
    tbody tr:nth-child(odd) {{
      background: rgba(15,23,42,0.65);
    }}
    tbody tr:hover {{
      background: rgba(30,64,175,0.35);
    }}
    code {{
      font-family: var(--mono);
      font-size: 11px;
      background: rgba(15,23,42,0.9);
      padding: 1px 4px;
      border-radius: 4px;
      border: 1px solid rgba(30,64,175,0.5);
    }}
    .status-badge {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    .status-green {{
      background: rgba(22,163,74,0.15);
      color: #4ade80;
      border: 1px solid rgba(34,197,94,0.6);
    }}
    .status-yellow {{
      background: rgba(234,179,8,0.15);
      color: #fde047;
      border: 1px solid rgba(234,179,8,0.6);
    }}
    .status-red {{
      background: rgba(248,113,113,0.15);
      color: #fecaca;
      border: 1px solid rgba(248,113,113,0.7);
    }}
    .col-idx {{ width: 36px; text-align: right; color: var(--text-muted); }}
    .col-status {{ width: 90px; }}
    .col-ns {{ width: 160px; }}
    .col-image code {{ word-break: break-all; }}
    .col-certs {{
      max-width: 420px;
    }}
    .ns-table-wrapper {{
      background: rgba(15,23,42,0.85);
      border-radius: 12px;
      border: 1px solid rgba(148,163,184,0.3);
      padding: 8px 10px 10px;
    }}
    .ns-table-caption {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin-bottom: 6px;
    }}
    .ns-table {{
      font-size: 12px;
      border-collapse: collapse;
      width: 100%;
    }}
    .ns-table th, .ns-table td {{
      padding: 4px 6px;
      border-bottom: 1px solid rgba(51,65,85,0.6);
    }}
    .ns-table th {{
      color: var(--text-muted);
      text-align: left;
      font-weight: 500;
      font-size: 11px;
    }}
    .ns-table td:first-child {{
      font-family: var(--mono);
      font-size: 11px;
    }}
    .ns-table tbody tr:nth-child(even) {{
      background: rgba(15,23,42,0.7);
    }}
    .ns-table tbody tr:nth-child(odd) {{
      background: rgba(15,23,42,0.5);
    }}
    .cert-block {{
      margin-bottom: 4px;
      border-radius: 6px;
      padding: 4px 6px;
      background: rgba(15,23,42,0.9);
      border: 1px solid rgba(31,41,55,0.9);
    }}
    .cert-block summary {{
      cursor: pointer;
      font-size: 11px;
      color: var(--text-muted);
      outline: none;
    }}
    .cert-block ul {{
      margin: 4px 0 0;
      padding-left: 18px;
    }}
    .cert-block li {{
      margin-bottom: 4px;
    }}
    .cert-block.bl {{
      border-color: rgba(239,68,68,0.8);
      box-shadow: 0 0 0 1px rgba(239,68,68,0.5);
    }}
    .cert-block.wl {{
      border-color: rgba(34,197,94,0.8);
      box-shadow: 0 0 0 1px rgba(34,197,94,0.45);
    }}
    .cert-block.nm {{
      border-color: rgba(148,163,184,0.5);
      box-shadow: 0 0 0 1px rgba(148,163,184,0.3);
    }}
    .pattern {{
      display: inline-block;
      font-size: 10px;
      color: var(--text-muted);
      border-radius: 999px;
      padding: 1px 5px;
      background: rgba(15,23,42,0.9);
      border: 1px solid rgba(148,163,184,0.7);
      margin-bottom: 2px;
    }}
    .cert-path {{
      font-size: 10px;
      background: rgba(15,23,42,0.9);
    }}
    .cert-subject {{
      font-size: 11px;
    }}
    .no-certs {{
      color: var(--text-muted);
      font-size: 11px;
    }}
    .footer-note {{
      margin-top: 16px;
      font-size: 11px;
      color: var(--text-muted);
      text-align: right;
    }}
  </style>
</head>
<body>
<div class="page">
  <h1>Kubernetes Image CA Report</h1>
  <div class="subtitle">
    Static analysis of container images &amp; their CA certificates.
  </div>

  <div class="summary-grid">
    <div class="card">
      <div class="card-title">Images scanned</div>
      <div class="card-value">{total_images}</div>
      <div class="card-label">Unique images across all namespaces</div>
    </div>
    <div class="card card-status-green">
      <div class="card-title">Green</div>
      <div class="card-value">{green_count}</div>
      <div class="card-label">Whitelisted certs only</div>
    </div>
    <div class="card card-status-yellow">
      <div class="card-title">Yellow</div>
      <div class="card-value">{yellow_count}</div>
      <div class="card-label">No blacklist, no whitelist</div>
    </div>
    <div class="card card-status-red">
      <div class="card-title">Red</div>
      <div class="card-value">{red_count}</div>
      <div class="card-label">At least one blacklisted cert</div>
    </div>
  </div>

  <div class="controls">
    <div class="controls-group">
      <span class="controls-label">Filter status</span>
      <label class="chip">
        <input type="checkbox" id="filter-green" checked>
        <span>Green</span>
      </label>
      <label class="chip">
        <input type="checkbox" id="filter-yellow" checked>
        <span>Yellow</span>
      </label>
      <label class="chip">
        <input type="checkbox" id="filter-red" checked>
        <span>Red</span>
      </label>
    </div>
    <div class="controls-group">
      <span class="controls-label">Search</span>
      <input type="text" id="search-box" class="search-input"
             placeholder="image, namespace, subject…">
    </div>
  </div>

  <div class="tables">
    <div class="main-table-wrapper">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Status</th>
            <th>Image</th>
            <th>Namespaces</th>
            <th>Certificates</th>
          </tr>
        </thead>
        <tbody id="images-tbody">
          {''.join(rows_html)}
        </tbody>
      </table>
    </div>
    <div class="ns-table-wrapper">
      <div class="ns-table-caption">Images per namespace</div>
      {ns_table_html}
    </div>
  </div>

  <div class="footer-note">
    Generated locally from report.json
  </div>
</div>

<script>
(function() {{
  const searchBox = document.getElementById('search-box');
  const cbGreen = document.getElementById('filter-green');
  const cbYellow = document.getElementById('filter-yellow');
  const cbRed = document.getElementById('filter-red');
  const rows = Array.from(document.querySelectorAll('.image-row'));

  function applyFilters() {{
    const text = (searchBox.value || '').toLowerCase();
    const showGreen = cbGreen.checked;
    const showYellow = cbYellow.checked;
    const showRed = cbRed.checked;

    rows.forEach(row => {{
      const status = row.getAttribute('data-status');
      const searchable = row.getAttribute('data-search') || '';

      let statusVisible = false;
      if (status === 'green' && showGreen) statusVisible = true;
      if (status === 'yellow' && showYellow) statusVisible = true;
      if (status === 'red' && showRed) statusVisible = true;
      if (status !== 'green' && status !== 'yellow' && status !== 'red') {{
        // unknown status shows if any filter is on
        statusVisible = (showGreen || showYellow || showRed);
      }}

      let textVisible = true;
      if (text && !searchable.includes(text)) {{
        textVisible = false;
      }}

      if (statusVisible && textVisible) {{
        row.style.display = '';
      }} else {{
        row.style.display = 'none';
      }}
    }});
  }}

  searchBox.addEventListener('input', applyFilters);
  cbGreen.addEventListener('change', applyFilters);
  cbYellow.addEventListener('change', applyFilters);
  cbRed.addEventListener('change', applyFilters);

  applyFilters();
}})();
</script>

</body>
</html>
"""
    return html_doc


def main():
    p = argparse.ArgumentParser(description="Generate fancy static HTML report from ca-analyse report.json")
    p.add_argument("--report", required=True, help="report.json produced by ca-analyse.py")
    p.add_argument("--output", "-o", required=False, help="output HTML file (default: stdout)")
    args = p.parse_args()

    report = load_json(args.report)
    if not isinstance(report, list):
        print("ERROR: report JSON must be a list", file=sys.stderr)
        sys.exit(1)

    html_str = build_html(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html_str)
    else:
        print(html_str)


if __name__ == "__main__":
    main()

