#!/usr/bin/env python3
"""
Anonymizer Web UI — Local web interface for document anonymization.

Finds a free port, launches Flask, opens the browser automatically.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from flask import Flask, render_template_string, request, redirect, url_for, send_file, flash, jsonify
from werkzeug.utils import secure_filename

TOOL_DIR = Path(__file__).parent
VAULTS_DIR = TOOL_DIR / "vaults"
CONFIG_PATH = TOOL_DIR / "config" / "default.json"

app = Flask(__name__)
app.secret_key = os.urandom(24)

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Anonymizer</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; }

  .layout { display: flex; min-height: 100vh; }
  .sidebar { width: 260px; background: #161b22; border-right: 1px solid #30363d; padding: 20px; flex-shrink: 0; }
  .main { flex: 1; padding: 30px; overflow-y: auto; }

  h1 { font-size: 18px; font-weight: 600; margin-bottom: 20px; color: #f0f0f0; }
  h2 { font-size: 15px; font-weight: 600; margin-bottom: 12px; color: #c9d1d9; }
  h3 { font-size: 13px; font-weight: 600; margin-bottom: 8px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; }

  .vault-list { list-style: none; margin-bottom: 20px; }
  .vault-list li { margin-bottom: 4px; }
  .vault-list a { display: block; padding: 8px 12px; border-radius: 6px; color: #c9d1d9; text-decoration: none; font-size: 14px; }
  .vault-list a:hover { background: #21262d; }
  .vault-list a.active { background: #1f6feb; color: #fff; }

  .btn { display: inline-block; padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 13px; font-weight: 500; text-decoration: none; transition: background 0.15s; }
  .btn-primary { background: #1f6feb; color: #fff; }
  .btn-primary:hover { background: #388bfd; }
  .btn-green { background: #238636; color: #fff; }
  .btn-green:hover { background: #2ea043; }
  .btn-red { background: #da3633; color: #fff; }
  .btn-red:hover { background: #f85149; }
  .btn-outline { background: transparent; border: 1px solid #30363d; color: #c9d1d9; }
  .btn-outline:hover { background: #21262d; }
  .btn-sm { padding: 5px 10px; font-size: 12px; }

  input[type="text"], input[type="password"], select {
    background: #0d1117; border: 1px solid #30363d; color: #e0e0e0; padding: 8px 12px;
    border-radius: 6px; font-size: 14px; width: 100%;
  }
  input:focus, select:focus { outline: none; border-color: #1f6feb; }

  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 13px; color: #8b949e; margin-bottom: 4px; }

  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }

  .upload-zone {
    border: 2px dashed #30363d; border-radius: 8px; padding: 40px; text-align: center;
    cursor: pointer; transition: border-color 0.2s, background 0.2s; margin-bottom: 20px;
  }
  .upload-zone:hover, .upload-zone.dragover { border-color: #1f6feb; background: #161b22; }
  .upload-zone input { display: none; }
  .upload-zone p { color: #8b949e; font-size: 14px; }
  .upload-zone .icon { font-size: 36px; margin-bottom: 10px; }

  .file-list { list-style: none; }
  .file-list li { display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }
  .file-list li:last-child { border-bottom: none; }

  .log { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; line-height: 1.6; white-space: pre-wrap; max-height: 400px; overflow-y: auto; color: #8b949e; }
  .log .entity { color: #58a6ff; }
  .log .warning { color: #d29922; }
  .log .error { color: #f85149; }
  .log .success { color: #3fb950; }

  .entity-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .entity-table th { text-align: left; padding: 8px; border-bottom: 2px solid #30363d; color: #8b949e; font-weight: 600; }
  .entity-table td { padding: 8px; border-bottom: 1px solid #21262d; }
  .entity-table .type { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .type-person { background: #1f3a5f; color: #58a6ff; }
  .type-organization { background: #2a1f3f; color: #bc8cff; }
  .type-address { background: #1f3f2a; color: #56d364; }
  .type-email, .type-phone, .type-iban, .type-ahv { background: #3f2a1f; color: #f0883e; }
  .type-amount, .type-date { background: #3f3a1f; color: #d29922; }
  .type-default { background: #21262d; color: #8b949e; }

  .flash { padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; font-size: 14px; }
  .flash-success { background: #1a3a1a; border: 1px solid #238636; color: #3fb950; }
  .flash-error { background: #3a1a1a; border: 1px solid #da3633; color: #f85149; }
  .flash-info { background: #1a2a3a; border: 1px solid #1f6feb; color: #58a6ff; }

  .actions { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
  .status-bar { display: flex; gap: 20px; margin-bottom: 20px; font-size: 13px; color: #8b949e; }
  .status-bar .value { color: #e0e0e0; font-weight: 500; }

  .tabs { display: flex; border-bottom: 1px solid #30363d; margin-bottom: 20px; }
  .tab { padding: 10px 16px; cursor: pointer; font-size: 14px; color: #8b949e; border-bottom: 2px solid transparent; }
  .tab:hover { color: #e0e0e0; }
  .tab.active { color: #e0e0e0; border-bottom-color: #1f6feb; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  .preview { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 16px; font-size: 13px; line-height: 1.6; white-space: pre-wrap; max-height: 500px; overflow-y: auto; }

  .empty-state { text-align: center; padding: 60px 20px; color: #484f58; }
  .empty-state .icon { font-size: 48px; margin-bottom: 16px; }
  .empty-state p { font-size: 14px; }

  .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #30363d; border-top-color: #1f6feb; border-radius: 50%; animation: spin 0.6s linear infinite; margin-right: 8px; vertical-align: middle; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="layout">
  <div class="sidebar">
    <h1>Anonymizer</h1>

    <h3>Vaults</h3>
    <ul class="vault-list">
      {% for v in vaults %}
      <li><a href="{{ url_for('vault_view', name=v) }}" class="{{ 'active' if vault and vault == v else '' }}">{{ v }}</a></li>
      {% endfor %}
      {% if not vaults %}
      <li style="color: #484f58; font-size: 13px; padding: 8px 12px;">No vaults yet</li>
      {% endif %}
    </ul>

    <h3>New vault</h3>
    <form method="POST" action="{{ url_for('create_vault') }}">
      <div class="form-group">
        <input type="text" name="name" placeholder="vault-name" required>
      </div>
      <div class="form-group">
        <label>Default locale</label>
        <select name="locale">
          <option value="fr_CH">French (CH)</option>
          <option value="de_CH">German (CH)</option>
          <option value="en_US">English (US)</option>
          <option value="en_GB">English (UK)</option>
          <option value="it_CH">Italian (CH)</option>
          <option value="de_DE">German (DE)</option>
          <option value="fr_FR">French (FR)</option>
        </select>
        <small style="color:#484f58;">Language auto-detected per document</small>
      </div>
      <div class="form-group">
        <input type="password" name="password" placeholder="Encryption password (optional)">
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%">Create vault</button>
    </form>
  </div>

  <div class="main">
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
    <div class="flash flash-{{ category }}">{{ message }}</div>
    {% endfor %}
    {% endwith %}

    <div class="empty-state">
      <div class="icon">&#128274;</div>
      <h2>Document Anonymizer</h2>
      <p>Create a vault or select one from the sidebar to start anonymizing documents.</p>
    </div>
  </div>
</div>

<script>
function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');
  document.getElementById(tabId).classList.add('active');
}

document.addEventListener('DOMContentLoaded', () => {
  // Upload zone drag-and-drop
  const zone = document.querySelector('.upload-zone');
  if (zone) {
    const input = zone.querySelector('input');
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
      e.preventDefault();
      zone.classList.remove('dragover');
      input.files = e.dataTransfer.files;
      zone.closest('form').submit();
    });
  }
});
</script>
</body>
</html>
"""

VAULT_CONTENT = """
<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
  <h2>{{ vault_name }}</h2>
  <div class="actions" style="margin-bottom:0;">
    <form method="POST" action="{{ url_for('delete_vault', name=vault_name) }}" onsubmit="return confirm('Delete vault {{ vault_name }} and all its files?')">
      <input type="hidden" name="password" value="{{ password or '' }}">
      <button type="submit" class="btn btn-red btn-sm">Delete vault</button>
    </form>
  </div>
</div>

<div class="status-bar">
  <div>Originals: <span class="value">{{ originals|length }}</span></div>
  <div>Anonymized: <span class="value">{{ anonymized|length }}</span></div>
  <div>Entities: <span class="value">{{ entities|length }}</span></div>
  <div>Encryption: <span class="value">{{ 'on' if encrypted else 'off' }}</span></div>
</div>

{% if needs_password %}
<div class="card">
  <h3>Unlock vault</h3>
  <p style="font-size:13px; color:#8b949e; margin-bottom:12px;">This vault is encrypted. Enter the password to access it.</p>
  <form method="GET" action="{{ url_for('vault_view', name=vault_name) }}">
    <div class="form-group">
      <input type="password" name="password" placeholder="Vault password" required style="width:300px;">
    </div>
    <button type="submit" class="btn btn-primary">Unlock</button>
  </form>
</div>
{% else %}

<!-- Upload -->
<div class="card">
  <h3>Upload documents</h3>
  <form method="POST" action="{{ url_for('upload_files', name=vault_name) }}" enctype="multipart/form-data">
    <input type="hidden" name="password" value="{{ password or '' }}">
    <div class="upload-zone">
      <input type="file" name="files" multiple accept=".docx,.pdf,.txt,.md,.html,.rtf,.pptx,.xlsx">
      <div class="icon">&#128196;</div>
      <p>Click or drag files here<br><small>.docx, .pdf, .txt, .md, .html</small></p>
    </div>
    <noscript><button type="submit" class="btn btn-primary">Upload</button></noscript>
  </form>
</div>

{% if originals %}
<!-- Originals -->
<div class="card">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
    <h3 style="margin:0;">Original files ({{ originals|length }})</h3>
    <div class="actions" style="margin-bottom:0;">
      <form method="POST" action="{{ url_for('run_anonymize', name=vault_name) }}" id="run-form">
        <input type="hidden" name="password" value="{{ password or '' }}">
        <button type="submit" class="btn btn-green" id="run-btn" onclick="this.innerHTML='<span class=spinner></span> Processing...'; this.disabled=true; this.form.submit();">
          Anonymize all
        </button>
      </form>
    </div>
  </div>
  <ul class="file-list">
    {% for f in originals %}
    <li>
      <span>{{ f }}</span>
      <form method="POST" action="{{ url_for('delete_file', name=vault_name, folder='originals', filename=f) }}" style="display:inline;">
        <input type="hidden" name="password" value="{{ password or '' }}">
        <button type="submit" class="btn btn-outline btn-sm">Remove</button>
      </form>
    </li>
    {% endfor %}
  </ul>
</div>
{% endif %}

{% if run_log %}
<div class="card">
  <h3>Last run log</h3>
  <div class="log">{{ run_log }}</div>
</div>
{% endif %}

{% if anonymized %}
<div class="card">
  <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
    <h3 style="margin:0;">Anonymized files ({{ anonymized|length }})</h3>
    <a href="{{ url_for('download_all_anonymized', name=vault_name) }}?password={{ password or '' }}" class="btn btn-primary btn-sm">Download all (.zip)</a>
  </div>
  <div class="tabs">
    {% for f in anonymized %}
    <div class="tab {{ 'active' if loop.first else '' }}" data-tab="anon-{{ loop.index }}" onclick="switchTab('anon-{{ loop.index }}')">{{ f }}</div>
    {% endfor %}
  </div>
  {% for f in anonymized %}
  <div class="tab-content {{ 'active' if loop.first else '' }}" id="anon-{{ loop.index }}">
    <div style="text-align:right; margin-bottom:8px;">
      <a href="{{ url_for('download_file', name=vault_name, folder='anonymized', filename=f) }}" class="btn btn-outline btn-sm">Download</a>
    </div>
    <div class="preview">{{ anonymized_contents[f] }}</div>
  </div>
  {% endfor %}
</div>
{% endif %}

{% if entities %}
<div class="card">
  <h3>Entity mapping ({{ entities|length }})</h3>
  <table class="entity-table">
    <thead><tr><th>Original</th><th>Replacement</th><th>Type</th><th>Detected by</th></tr></thead>
    <tbody>
    {% for orig, info in entities.items() %}
    <tr>
      <td>{{ orig[:50] }}</td>
      <td>{{ info.replacement[:50] }}</td>
      <td><span class="entity-table .type type-{{ info.type if info.type in ['person','organization','address','email','phone','iban','ahv','amount'] else 'default' }}">{{ info.type }}</span></td>
      <td>{{ info.detected_by }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<!-- De-anonymize -->
{% if anonymized %}
<div class="card">
  <h3>De-anonymize output</h3>
  <p style="font-size:13px; color:#8b949e; margin-bottom:12px;">Upload files that Claude produced from the anonymized documents. They will be de-anonymized using this vault's mapping.</p>
  <form method="POST" action="{{ url_for('run_deanonymize', name=vault_name) }}" enctype="multipart/form-data">
    <input type="hidden" name="password" value="{{ password or '' }}">
    <input type="file" name="files" multiple accept=".md,.txt" style="margin-bottom:12px;">
    <button type="submit" class="btn btn-primary">De-anonymize</button>
  </form>
  {% if deanonymized %}
  <div style="margin-top:16px;">
    <h3>De-anonymized files</h3>
    <ul class="file-list">
      {% for f in deanonymized %}
      <li>
        <span>{{ f }}</span>
        <a href="{{ url_for('download_file', name=vault_name, folder='deanonymized', filename=f) }}" class="btn btn-outline btn-sm">Download</a>
      </li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}
</div>
{% endif %}

{% endif %}{# end needs_password else #}
"""


def get_vaults():
    if not VAULTS_DIR.exists():
        return []
    return sorted([d.name for d in VAULTS_DIR.iterdir() if d.is_dir()])


def load_config():
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def get_vault_state(vault_name, password=None):
    vault_path = VAULTS_DIR / vault_name
    originals = sorted([f.name for f in (vault_path / "originals").iterdir() if f.is_file()]) if (vault_path / "originals").exists() else []
    anonymized = sorted([f.name for f in (vault_path / "anonymized").iterdir() if f.is_file()]) if (vault_path / "anonymized").exists() else []
    deanonymized = sorted([f.name for f in (vault_path / "deanonymized").iterdir() if f.is_file()]) if (vault_path / "deanonymized").exists() else []

    encrypted = (vault_path / "mapping.enc").exists()
    needs_password = encrypted and not password

    # Load entities
    entities = {}
    if not needs_password:
        try:
            from lib.replacer import MappingTable
            mapping = MappingTable(vault_path, password=password)
            entities = mapping.entities
        except (SystemExit, Exception):
            pass

    # Load anonymized file contents for preview
    anonymized_contents = {}
    for f in anonymized:
        try:
            content = (vault_path / "anonymized" / f).read_text(encoding="utf-8")
            anonymized_contents[f] = content
        except Exception:
            anonymized_contents[f] = "(could not read)"

    # Load run log
    run_log = ""
    log_path = vault_path / ".last_run.log"
    if log_path.exists():
        run_log = log_path.read_text(encoding="utf-8")

    return {
        "originals": originals,
        "anonymized": anonymized,
        "deanonymized": deanonymized,
        "encrypted": encrypted,
        "needs_password": needs_password,
        "entities": entities,
        "anonymized_contents": anonymized_contents,
        "run_log": run_log,
    }


@app.route("/")
def index():
    return render_template_string(TEMPLATE, vaults=get_vaults(), vault=None)


@app.route("/vault/<name>")
def vault_view(name):
    password = request.args.get("password", "")
    state = get_vault_state(name, password=password or None)
    if state.get("needs_password"):
        flash("This vault is encrypted. Enter the password to unlock.", "info")
    combined = TEMPLATE.replace(
        """<div class="empty-state">
      <div class="icon">&#128274;</div>
      <h2>Document Anonymizer</h2>
      <p>Create a vault or select one from the sidebar to start anonymizing documents.</p>
    </div>""",
        VAULT_CONTENT,
    )
    return render_template_string(
        combined,
        vaults=get_vaults(),
        vault=name,
        vault_name=name,
        password=password,
        **state,
    )


@app.route("/create", methods=["POST"])
def create_vault():
    name = request.form["name"].strip().lower().replace(" ", "-")
    locale = request.form.get("locale", "fr_CH")
    password = request.form.get("password", "").strip() or None

    vault_path = VAULTS_DIR / name
    if vault_path.exists():
        flash(f"Vault '{name}' already exists.", "error")
        return redirect(url_for("index"))

    for subdir in ("originals", "anonymized", "deanonymized"):
        (vault_path / subdir).mkdir(parents=True)

    from lib.replacer import MappingTable
    mapping = MappingTable(vault_path, locale=locale, password=password)
    mapping.save()

    flash(f"Vault '{name}' created.", "success")
    return redirect(url_for("vault_view", name=name, password=password or ""))


@app.route("/vault/<name>/upload", methods=["POST"])
def upload_files(name):
    password = request.form.get("password", "")
    vault_path = VAULTS_DIR / name / "originals"
    files = request.files.getlist("files")
    count = 0
    for f in files:
        if f.filename:
            filename = secure_filename(f.filename)
            f.save(vault_path / filename)
            count += 1
    flash(f"{count} file(s) uploaded.", "success")
    return redirect(url_for("vault_view", name=name, password=password))


@app.route("/vault/<name>/run", methods=["POST"])
def run_anonymize(name):
    password = request.form.get("password", "").strip() or None
    vault_path = VAULTS_DIR / name

    # Run the CLI and capture output
    cmd = [sys.executable, str(TOOL_DIR / "anonymize.py"), "run", name]
    if password:
        cmd += ["--password", password]

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(TOOL_DIR), timeout=600)
    output = result.stdout + result.stderr

    # Save log
    (vault_path / ".last_run.log").write_text(output, encoding="utf-8")

    if result.returncode == 0:
        flash("Anonymization complete.", "success")
    elif result.returncode == 2:
        flash("Anonymization complete with CRITICAL findings — review the log.", "error")
    else:
        flash(f"Anonymization failed (exit code {result.returncode}).", "error")

    return redirect(url_for("vault_view", name=name, password=password or ""))


@app.route("/vault/<name>/deanonymize", methods=["POST"])
def run_deanonymize(name):
    password = request.form.get("password", "").strip() or None
    vault_path = VAULTS_DIR / name

    # Save uploaded files to a temp dir, then deanonymize
    files = request.files.getlist("files")
    tmp_dir = vault_path / ".tmp_deanon"
    tmp_dir.mkdir(exist_ok=True)

    for f in files:
        if f.filename:
            f.save(tmp_dir / secure_filename(f.filename))

    cmd = [sys.executable, str(TOOL_DIR / "deanonymize.py"), name, str(tmp_dir)]
    if password:
        cmd += ["--password", password]

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(TOOL_DIR), timeout=120)

    # Clean up temp dir
    shutil.rmtree(tmp_dir, ignore_errors=True)

    if result.returncode == 0:
        flash("De-anonymization complete.", "success")
    else:
        flash(f"De-anonymization failed: {result.stderr}", "error")

    return redirect(url_for("vault_view", name=name, password=password or ""))


@app.route("/vault/<name>/delete", methods=["POST"])
def delete_vault(name):
    vault_path = VAULTS_DIR / name
    if vault_path.exists():
        shutil.rmtree(vault_path)
        flash(f"Vault '{name}' deleted.", "info")
    return redirect(url_for("index"))


@app.route("/vault/<name>/delete-file/<folder>/<filename>", methods=["POST"])
def delete_file(name, folder, filename):
    password = request.form.get("password", "")
    file_path = VAULTS_DIR / name / folder / filename
    if file_path.exists():
        file_path.unlink()
    return redirect(url_for("vault_view", name=name, password=password))


@app.route("/vault/<name>/download/<folder>/<filename>")
def download_file(name, folder, filename):
    return send_file(VAULTS_DIR / name / folder / filename, as_attachment=True)


@app.route("/vault/<name>/download-all-anonymized")
def download_all_anonymized(name):
    import zipfile
    import io

    vault_path = VAULTS_DIR / name / "anonymized"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in vault_path.iterdir():
            if f.is_file():
                zf.write(f, f.name)
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=f"{name}-anonymized.zip")


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def open_browser(port):
    """Open browser after a short delay to let Flask start."""
    import time
    time.sleep(1.0)
    url = f"http://localhost:{port}"
    # In WSL, webbrowser.open launches a Linux browser. Use cmd.exe to open Windows default browser.
    if "microsoft" in os.uname().release.lower():
        subprocess.Popen(["cmd.exe", "/c", "start", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        webbrowser.open(url)




if __name__ == "__main__":
    port = find_free_port()
    print(f"\n  Anonymizer UI running at: http://localhost:{port}\n")

    # Open browser in background
    threading.Thread(target=open_browser, args=(port,), daemon=True).start()

    app.run(host="127.0.0.1", port=port, debug=False)
