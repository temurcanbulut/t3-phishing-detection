"""Local URL analysis application. Run with python app.py."""

import os
from threading import BoundedSemaphore

from analysis import InvalidTarget, analyze_url
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
app.config["TRUSTED_HOSTS"] = ["localhost", "127.0.0.1", "[::1]"]
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
        "index.html",
        safe_browsing_enabled=bool(os.getenv("SAFE_BROWSING_API_KEY")),
        runtime="local",
        asset_prefix="static",
    )


@app.errorhandler(400)
def bad_request(_error):
    return jsonify(error="İstek biçimi veya Host başlığı geçersiz."), 400


def run_analysis(value, active=False, threat_lookup=False):
    if not analysis_slots.acquire(blocking=False):
        return jsonify(error="Analizler sürüyor. Biraz sonra yeniden deneyin."), 429
    try:
        return jsonify(
            analyze_url(
                value,
                os.getenv("SAFE_BROWSING_API_KEY", ""),
                active=active,
                threat_lookup=threat_lookup,
            )
        )
    except InvalidTarget as error:
        return jsonify(error=str(error)), 400
    finally:
        analysis_slots.release()


@app.post("/api/analyze")
def analyze():
    origin = request.headers.get("Origin")
    if origin and origin != request.host_url.rstrip("/"):
        return jsonify(error="Farklı bir web sitesinden analiz isteği kabul edilmez."), 403
    if not request.is_json:
        return jsonify(error="JSON biçiminde bir URL gönderin."), 415
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Geçerli bir JSON nesnesi gönderin."), 400
    for key in ("active", "threat_lookup"):
        if key in payload and not isinstance(payload[key], bool):
            return jsonify(error="Analiz seçenekleri true/false olmalıdır."), 400
    return run_analysis(
        payload.get("url"), payload.get("active", False), payload.get("threat_lookup", False)
    )


@app.get("/check_domain")
def check_domain():
    return jsonify(error="URL içeren GET uç noktası kaldırıldı. POST /api/analyze kullanın."), 405


@app.errorhandler(413)
def too_large(_error):
    return (
        jsonify(error="İstek çok büyük. En fazla 2048 karakterlik URL kullanın."),
        413,
    )


if __name__ == "__main__":
    from waitress import serve

    print("T3 URL & Domain Inspector: http://127.0.0.1:5000")
    serve(
        app,
        host="127.0.0.1",
        port=5000,
        threads=8,
        max_request_body_size=4096,
        max_request_header_size=16384,
        connection_limit=32,
        backlog=32,
        channel_timeout=15,
        cleanup_interval=5,
    )
