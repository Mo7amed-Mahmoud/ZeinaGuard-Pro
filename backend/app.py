"""ZeinaGuard Pro backend application factory."""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.auth import AuthService
from backend.config import load_backend_settings
from backend.models import db
from backend.routes import register_blueprints
from backend.websocket_server import init_socketio


def create_app() -> Flask:
    settings = load_backend_settings()
    app = Flask(__name__)
    app.config.update(settings.flask_config)
    app.extensions["zeinaguard.settings"] = settings

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": list(settings.cors_origins),
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True,
            },
            r"/socket.io/*": {
                "origins": list(settings.cors_origins),
                "supports_credentials": True,
            },
        },
    )

    db.init_app(app)
    AuthService(app)
    socketio = init_socketio(app)
    app.socketio = socketio
    register_blueprints(app)
    _register_core_routes(app)

    with app.app_context():
        db.create_all()
        app.logger.info("Database tables created or verified")

    return app


def _register_core_routes(app: Flask) -> None:
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "zeinaguard-backend"}), 200

    @app.route("/", methods=["GET"])
    def root():
        settings = app.extensions["zeinaguard.settings"]
        return jsonify(
            {
                "service": "ZeinaGuard Pro Backend",
                "version": "2.0.0",
                "status": "running",
                "environment": settings.environment,
                "endpoints": {
                    "auth": "/api/auth/login",
                    "threats": "/api/threats",
                    "sensors": "/api/sensors",
                    "alerts": "/api/alerts",
                    "analytics": "/api/analytics",
                    "users": "/api/users",
                    "topology": "/api/topology",
                },
            }
        ), 200

    @app.route("/api/status", methods=["GET"])
    def api_status():
        settings = app.extensions["zeinaguard.settings"]
        return jsonify(
            {
                "api": "operational",
                "database": "ready",
                "detection_engine": "active",
                "trusted_ssids": sorted(settings.trusted_aps.keys()),
                "version": "2.0.0",
            }
        ), 200

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Not found", "code": 404}), 404

    @app.errorhandler(500)
    def internal_error(_error):
        return jsonify({"error": "Internal server error", "code": 500}), 500


app = create_app()


if __name__ == "__main__":
    settings = app.extensions["zeinaguard.settings"]
    app.socketio.run(
        app,
        host=settings.host,
        port=settings.port,
        debug=settings.debug,
        allow_unsafe_werkzeug=True,
    )
