#!/usr/bin/env python3
"""Render the MCP Shield PRD set (markdown + architecture.svg) into one PDF via headless Chrome."""
import json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent
DOCS = [
    ("master-plan.md", "1 · Master Plan"),
    ("implementation-plan.md", "2 · Implementation Plan"),
    ("design-guideline.md", "3 · Design Guideline"),
    ("user-journey.md", "4 · User Journey"),
    ("tasks.md", "5 · Tasks"),
]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

svg = (ROOT / "architecture.svg").read_text()
docs = []
for fname, title in DOCS:
    md = (ROOT / fname).read_text().replace("<!-- ARCH_SVG -->", '<div class="arch">' + svg + "</div>")
    docs.append({"id": fname.split(".")[0], "title": title, "md": md})

html = """<!doctype html><html><head><meta charset="utf-8"><title>MCP Shield PRD</title>
<script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>
<style>
@page { size: A4 landscape; margin: 14mm 14mm 16mm; }
* { box-sizing: border-box; }
body { font: 10.5px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; color: #0f172a; margin: 0; }
h1 { font-size: 22px; color: #0f766e; border-bottom: 2px solid #0d9488; padding-bottom: 6px; margin: 0 0 10px; }
h2 { font-size: 15px; color: #0f172a; margin: 18px 0 6px; border-left: 4px solid #0d9488; padding-left: 8px; break-after: avoid; }
h3 { font-size: 12.5px; margin: 12px 0 4px; break-after: avoid; }
h4 { font-size: 11px; margin: 10px 0 4px; color: #334155; }
p, li { margin: 3px 0; }
code { font-family: "JetBrains Mono", Menlo, monospace; font-size: 9.2px; background: #f1f5f9; padding: 0 3px; border-radius: 3px; }
pre { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; font-size: 9px; line-height: 1.35; white-space: pre-wrap; break-inside: avoid; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 10px; font-size: 9px; }
th { background: #0f766e; color: #fff; text-align: left; font-weight: 600; }
th, td { border: 1px solid #cbd5e1; padding: 3px 5px; vertical-align: top; }
tr:nth-child(even) td { background: #f8fafc; }
tr { break-inside: avoid; }
.doc { break-before: page; }
.arch { break-inside: avoid; border: 1px solid #e2e8f0; border-radius: 8px; padding: 6px; margin: 8px 0; }
.mermaid { text-align: center; break-inside: avoid; margin: 8px 0; }
.mermaid svg { max-height: 120mm; }
.cover { height: 175mm; display: flex; flex-direction: column; justify-content: center; }
.cover .eyebrow { color: #0f766e; font-weight: 700; letter-spacing: 2px; font-size: 12px; }
.cover h1 { font-size: 40px; border: 0; margin: 6px 0; color: #0f172a; }
.cover .sub { font-size: 16px; color: #334155; max-width: 190mm; }
.cover dl { display: grid; grid-template-columns: 40mm auto; gap: 4px 10px; margin-top: 18mm; font-size: 12px; }
.cover dt { color: #64748b; } .cover dd { margin: 0; font-weight: 600; }
.toc ol { font-size: 13px; line-height: 2; }
.arch-page h1 { margin-bottom: 4px; }
</style></head><body>
<section class="cover">
  <div class="eyebrow">PRODUCT REQUIREMENTS DOCUMENT</div>
  <h1>MCP Shield</h1>
  <div class="sub">A security &amp; observability gateway for Model Context Protocol servers. It blocks prompt-injection and tool poisoning, enforces policy, asks humans before risky calls, and audits every MCP request with its token usage.</div>
  <dl>
    <dt>Version</dt><dd>PRD v1.1 — Gate 1 draft, revised after MCP review</dd>
    <dt>Protocol</dt><dd>MCP 2026-07-28 + legacy 2025-11-25 · Python SDK v2</dd>
    <dt>Date</dt><dd>2026-11-18</dd>
    <dt>Template</dt><dd>Weihan96/PRD-templates · template/v4</dd>
    <dt>Documents</dt><dd>Master Plan · Implementation Plan · Design Guideline · User Journey · Tasks</dd>
  </dl>
</section>
<section class="doc toc"><h1>Contents</h1><ol>
  <li>System Architecture (overview diagram)</li>
  <li>Master Plan — users, scope, domain terms, stack, pages, risks</li>
  <li>Implementation Plan — boundaries, pipeline, token metering, schema, verification</li>
  <li>Design Guideline — dashboard pages, in-client copy, states</li>
  <li>User Journey — setup, attack demo, approvals, audit flows</li>
  <li>Tasks — 3-wave execution backlog</li>
</ol></section>
<section class="doc arch-page"><h1>System Architecture</h1>
<p>Every client request flows through the security pipeline (top row) to the upstream servers. Responses flow back through validation, scanning, redaction and context-budget enforcement (second row). Each stage reports to the Token Meter and the async Audit Logger, which writes one row per JSON-RPC request to SQLite. The two legs of an approved call share a logical call ID. Approval is a multi-round-trip: Shield returns the question and the client retries the call with the answer, because the 2026-07-28 protocol has no server-to-client requests. The Streamlit dashboard and the optional <code>shield_*</code> tools read the audit store.</p>
<div class="arch">__SVG__</div></section>
<div id="docs"></div>
<script>
const DOCS = __DOCS__;
const root = document.getElementById('docs');
for (const d of DOCS) {
  const s = document.createElement('section');
  s.className = 'doc'; s.id = d.id;
  s.innerHTML = marked.parse(d.md, { gfm: true });
  root.appendChild(s);
}
document.querySelectorAll('pre code.language-mermaid').forEach(c => {
  const div = document.createElement('div');
  div.className = 'mermaid'; div.textContent = c.textContent;
  c.parentElement.replaceWith(div);
});
mermaid.initialize({ startOnLoad: false, theme: 'neutral', securityLevel: 'loose', flowchart: { htmlLabels: false } });
mermaid.run({ querySelector: '.mermaid' })
  .catch(e => console.error(e))
  .finally(() => { document.title = 'READY'; });
</script></body></html>"""

html = html.replace("__SVG__", svg).replace("__DOCS__", json.dumps(docs))
out_html = ROOT / "mcp-shield-prd.html"
out_html.write_text(html)

pdf = ROOT / "MCP-Shield-PRD.pdf"
subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                "--virtual-time-budget=25000", "--run-all-compositor-stages-before-draw",
                f"--print-to-pdf={pdf}", out_html.as_uri()], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Standalone architecture PNG
arch_html = ROOT / ".arch.html"
arch_html.write_text('<html><body style="margin:0;background:#fff">' + svg.replace('width="100%"', 'width="1800"') + "</body></html>")
subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--window-size=1800,1200",
                f"--screenshot={ROOT / 'architecture.png'}", arch_html.as_uri()], check=True,
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
arch_html.unlink()
print(f"PDF: {pdf}\nPNG: {ROOT / 'architecture.png'}")
