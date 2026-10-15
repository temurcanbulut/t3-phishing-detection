"""Local URL analysis application. Run with python app.py."""

import os
from threading import BoundedSemaphore

from flask import Flask, jsonify, render_template, request

from analysis import InvalidTarget, analyze_url

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
analysis_slots = BoundedSemaphore(4)


@app.after_request
def response_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self'; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    return response


@app.get("/")
def index():
    return render_template(
        "index.html", safe_browsing_enabled=bool(os.getenv("SAFE_BROWSING_API_KEY"))
    )


def run_analysis(value):
    if not analysis_slots.acquire(blocking=False):
        return jsonify(error="Analizler sürüyor. Biraz sonra yeniden deneyin."), 429
    try:
        return jsonify(analyze_url(value, os.getenv("SAFE_BROWSING_API_KEY", "")))
    except InvalidTarget as error:
        return jsonify(error=str(error)), 400
    finally:
        analysis_slots.release()


@app.post("/api/analyze")
def analyze():
    if not request.is_json:
        return jsonify(error="JSON biçiminde bir URL gönderin."), 415
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Geçerli bir JSON nesnesi gönderin."), 400
    return run_analysis(payload.get("url"))


@app.get("/check_domain")
def check_domain():
    """Retain the old route with the documented report response schema."""
    return run_analysis(request.args.get("domain"))


@app.errorhandler(413)
def too_large(_error):
    return (
        jsonify(error="İstek çok büyük. En fazla 2048 karakterlik URL kullanın."),
        413,
    )


if __name__ == "__main__":
    from waitress import serve

    print("T3 Phishing Detection: http://127.0.0.1:5000")
    serve(app, host="127.0.0.1", port=5000, threads=8)
