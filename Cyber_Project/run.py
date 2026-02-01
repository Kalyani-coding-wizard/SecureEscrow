#!/usr/bin/env python3
"""
Secure Digital Escrow Platform
Entry point for the Flask application.
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
