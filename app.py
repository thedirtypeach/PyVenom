'''
Local web UI for PyVenom.

    python app.py      then open http://127.0.0.1:5000

Listens on 127.0.0.1 only: the page starts nmap scans, so it must not be reachable
from the network.
'''

import secrets

from flask import Flask, abort, render_template, request
from markupsafe import Markup, escape

import pyvenom

app = Flask(__name__)

# Sent in the page and required on every scan. Other websites open in the same browser
# cannot read it, so they cannot make the browser start scans here (CSRF).
TOKEN = secrets.token_urlsafe(32)


@app.before_request
def local_only():
    # A DNS-rebinding page reaches 127.0.0.1 under its own hostname; refuse those.
    if request.host.rsplit(":", 1)[0] not in ("127.0.0.1", "localhost"):
        abort(403)


@app.template_filter()
def linkify(text):
    '''Escape text and turn https:// words into links.'''
    words = [Markup(f'<a href="{escape(w)}">{escape(w)}</a>') if w.startswith("https://") else escape(w)
             for w in text.split(" ")]
    return Markup(" ").join(words)


@app.get("/")
def index():
    return render_template("index.html", token=TOKEN, target=pyvenom.get_local_ip(),
                           ports=pyvenom.DEFAULT_PORTS)


@app.post("/scan")
def scan():
    if not secrets.compare_digest(request.form.get("token", ""), TOKEN):
        abort(403)
    target = request.form.get("target", "").strip() or pyvenom.get_local_ip()
    ports = request.form.get("ports", "").strip() or pyvenom.DEFAULT_PORTS
    try:
        findings, error = pyvenom.run_scan(target, ports), None
    except pyvenom.ScanError as e:
        findings, error = None, str(e)
    return render_template("index.html", token=TOKEN, target=target, ports=ports, error=error,
                           findings=findings, sources=pyvenom.cited_sources(findings or []))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
