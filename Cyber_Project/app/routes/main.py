"""
Main routes for the Secure Escrow Platform.
Handles landing page and general navigation.
"""

from flask import Blueprint, render_template
from flask_login import current_user

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Landing page."""
    return render_template('main/index.html')


@main_bp.route('/about')
def about():
    """About page explaining the platform."""
    return render_template('main/about.html')
