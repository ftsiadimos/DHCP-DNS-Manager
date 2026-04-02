#!/usr/bin/env python3
"""Application entry point."""

from app.routes import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=1053, debug=True)
