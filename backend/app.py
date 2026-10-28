"""
PHISH GUARD - Next-Gen Hybrid AI Browser Security Backend
Flask RESTful API server for real-time multi-modal phishing detection,
DOM & form analysis, visual brand verification, SOC telemetry, and threat response.
"""

import csv
import io
import os
import sys
import time
from typing import Any, Dict
from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

# Add root directory to path for modular imports
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)
sys.path.append(os.path.dirname(__file__))

import config
import database_manager
from logger import setup_logger
from model_service import predictor_service
from security_utils import (
    add_security_headers,
    rate_limit,
    sanitize_string,
    validate_and_sanitize_url
)

logger = setup_logger("phishguard.api")

DASHBOARD_DIR = os.path.join(BASE_DIR, "admin_dashboard")
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "screenshots")
MODELS_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

app = Flask(__name__, static_folder=DASHBOARD_DIR)
CORS(app, resources={r"/*": {"origins": "*"}})

START_TIME = time.time()


@app.after_request
def apply_security_headers(response):
    """Applies OWASP security headers to every response."""
    return add_security_headers(response)


# ==========================================
# Frontend & Asset Routes
# ==========================================

@app.route("/", methods=["GET"])
@app.route("/dashboard", methods=["GET"])
def serve_dashboard():
    """Serves the Admin Dashboard single page application."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/css/<path:path>", methods=["GET"])
def serve_dashboard_css(path):
    """Serves CSS assets for Admin Dashboard."""
    return send_from_directory(os.path.join(DASHBOARD_DIR, "css"), path)


@app.route("/js/<path:path>", methods=["GET"])
def serve_dashboard_js(path):
    """Serves JavaScript assets for Admin Dashboard."""
    return send_from_directory(os.path.join(DASHBOARD_DIR, "js"), path)


@app.route("/screenshots/<path:filename>", methods=["GET"])
def serve_screenshot(filename):
    """Serves captured verification screenshot images."""
    return send_from_directory(SCREENSHOTS_DIR, filename)


@app.route("/models/<path:filename>", methods=["GET"])
def serve_model_artifact(filename):
    """Serves model evaluation artifacts (ROC curves, confusion matrix)."""
    return send_from_directory(MODELS_DIR, filename)


# ==========================================
# Hybrid AI Detection Endpoints
# ==========================================

@app.route("/predict-hybrid", methods=["POST"])
@rate_limit
def predict_hybrid():
    """
    POST /predict-hybrid
    Primary Multi-Modal Inspection Endpoint.
    Receives:
    {
      "url": "http://example.com",
      "html": "<html>...</html>",
      "forms": [...],
      "scripts": [...],
      "images": [...],
      "screenshot": "data:image/jpeg;base64,...",
      "dom_metrics": {...},
      "favicon_url": "https://..."
    }
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request payload must be JSON."}), 400

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url")
    if not raw_url:
        return jsonify({"status": "error", "message": "Missing required field: 'url'."}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
    client_ip = client_ip.split(",")[0].strip()

    logger.info(f"Hybrid inspection initiated for URL: {raw_url[:80]} from {client_ip}")

    result = predictor_service.predict_hybrid(
        raw_url=raw_url,
        html_content=data.get("html", ""),
        forms_data=data.get("forms", []),
        scripts_data=data.get("scripts", []),
        images_data=data.get("images", []),
        screenshot_base64=data.get("screenshot"),
        dom_metrics=data.get("dom_metrics", {}),
        favicon_url=data.get("favicon_url", ""),
        client_ip=client_ip
    )

    if not result.get("success", False):
        return jsonify({"status": "error", "message": result.get("error", "Inspection failed")}), 400

    return jsonify({
        "status": "success",
        "data": result
    }), 200


@app.route("/predict", methods=["POST"])
@rate_limit
def predict_legacy():
    """
    POST /predict
    Backwards-compatible URL-only prediction endpoint.
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be JSON with 'url' field."}), 400

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url")
    if not raw_url:
        return jsonify({"status": "error", "message": "Missing required field: 'url'."}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
    client_ip = client_ip.split(",")[0].strip()

    result = predictor_service.predict_url(raw_url=raw_url, client_ip=client_ip)

    if not result.get("success", False):
        return jsonify({"status": "error", "message": result.get("error", "Invalid URL")}), 400

    return jsonify({
        "status": "success",
        "data": result
    }), 200


@app.route("/report", methods=["POST"])
@rate_limit
def report():
    """
    POST /report
    Submits user feedback for model retraining and threat intelligence.
    """
    if not request.is_json:
        return jsonify({"status": "error", "message": "Request must be JSON."}), 400

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()
    feedback = data.get("feedback", "").strip().lower()

    if not raw_url or feedback not in ["false_positive", "false_negative"]:
        return jsonify({
            "status": "error",
            "message": "Valid 'url' and 'feedback' ('false_positive' or 'false_negative') are required."
        }), 400

    reported_type = sanitize_string(data.get("reported_type", ""))
    actual_status = sanitize_string(data.get("actual_status", ""))
    comments = sanitize_string(data.get("comments", ""))

    report_id = database_manager.add_report(
        url=raw_url,
        feedback=feedback,
        reported_type=reported_type,
        actual_status=actual_status,
        comments=comments
    )

    logger.info(f"User report recorded (#{report_id}) for {raw_url} [{feedback}]")

    return jsonify({
        "status": "success",
        "message": "Feedback submitted successfully. Thank you for contributing to Phish Guard intelligence.",
        "report_id": report_id
    }), 201


@app.route("/history", methods=["GET"])
def get_history():
    """GET /history: Retrieves paginated multi-layer scan records."""
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        limit = 50
        offset = 0

    status = request.args.get("status")
    search = request.args.get("search")

    history, total = database_manager.get_scan_history(
        limit=limit,
        offset=offset,
        filter_status=status,
        search=search
    )

    return jsonify({
        "status": "success",
        "total": total,
        "limit": limit,
        "offset": offset,
        "history": history
    }), 200


@app.route("/stats", methods=["GET"])
def get_stats():
    """GET /stats: Returns aggregated SOC telemetry, brand attacks, and threat heatmap."""
    stats = database_manager.get_dashboard_statistics()
    return jsonify({
        "status": "success",
        "stats": stats
    }), 200


@app.route("/model-info", methods=["GET"])
def model_info():
    """GET /model-info: Returns details about champion model, ROC metrics, and multi-model benchmarks."""
    info = predictor_service.get_model_information()
    return jsonify({
        "status": "success",
        "data": info
    }), 200


@app.route("/blacklist", methods=["GET", "POST", "DELETE"])
def manage_blacklist():
    """CRUD operations for blacklisted domains and patterns."""
    if request.method == "GET":
        items = database_manager.get_blacklist()
        return jsonify({"status": "success", "count": len(items), "blacklist": items}), 200

    elif request.method == "POST":
        data = request.get_json(silent=True) or {}
        pattern = sanitize_string(data.get("pattern", ""))
        domain = sanitize_string(data.get("domain", pattern))
        reason = sanitize_string(data.get("reason", "Added via Admin API"))

        if not pattern:
            return jsonify({"status": "error", "message": "Pattern/Domain is required."}), 400

        entry_id = database_manager.add_to_blacklist(
            pattern=pattern,
            domain=domain,
            reason=reason,
            added_by="admin"
        )
        return jsonify({
            "status": "success",
            "message": f"Successfully blacklisted '{pattern}'.",
            "id": entry_id
        }), 201

    elif request.method == "DELETE":
        item_id = request.args.get("id")
        if not item_id and request.is_json:
            item_id = (request.get_json(silent=True) or {}).get("id")

        if not item_id:
            return jsonify({"status": "error", "message": "Blacklist item 'id' is required."}), 400

        try:
            item_id = int(item_id)
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid item ID."}), 400

        removed = database_manager.remove_from_blacklist(item_id)
        if removed:
            return jsonify({"status": "success", "message": f"Blacklist entry {item_id} removed."}), 200
        else:
            return jsonify({"status": "error", "message": "Entry not found."}), 404


@app.route("/reports", methods=["GET"])
def list_reports():
    """GET /reports: Retrieves all feedback reports."""
    reports = database_manager.get_reports()
    return jsonify({"status": "success", "count": len(reports), "reports": reports}), 200


@app.route("/export-scans", methods=["GET"])
def export_scans():
    """GET /export-scans: Exports audit logs as CSV for compliance and academic reporting."""
    history, _ = database_manager.get_scan_history(limit=500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "URL", "Domain", "Prediction", "Confidence", "Risk_Level", "Hybrid_Score", "Latency_MS"])

    for r in history:
        writer.writerow([
            r.get("id"),
            r.get("created_at"),
            r.get("url"),
            r.get("domain"),
            r.get("prediction"),
            r.get("confidence"),
            r.get("risk_level"),
            r.get("hybrid_score", 0.0),
            r.get("scan_time_ms")
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=phishguard_audit_scans.csv"}
    )


@app.route("/api/settings", methods=["GET", "POST"])
def manage_settings():
    """GET /api/settings: View all settings | POST: Update a setting."""
    if request.method == "GET":
        settings = database_manager.get_settings()
        return jsonify({"status": "success", "settings": settings}), 200

    elif request.method == "POST":
        data = request.get_json(silent=True) or {}
        key = sanitize_string(data.get("key", ""))
        value = sanitize_string(data.get("value", ""))

        if not key or not value:
            return jsonify({"status": "error", "message": "Key and value are required."}), 400

        updated = database_manager.update_setting(key, value)
        return jsonify({"status": "success" if updated else "error", "message": "Setting updated."}), 200


@app.route("/health", methods=["GET"])
def health():
    """GET /health: Operational readiness check."""
    uptime = round(time.time() - START_TIME, 1)
    return jsonify({
        "status": "healthy",
        "service": "PHISH GUARD Hybrid Security Engine",
        "version": "2.0.0-Hybrid",
        "uptime_seconds": uptime,
        "database_connected": True,
        "ml_engine_loaded": predictor_service.model is not None,
        "hybrid_engine_loaded": predictor_service.model is not None,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }), 200


if __name__ == "__main__":
    logger.info(f"Starting PHISH GUARD Hybrid Backend on http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
