from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os

from .config import Config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()

# Server-side encryption key (Fernet)
fernet = None


def create_app(config_class=Config):
    """Application factory pattern."""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'
    login_manager.login_message = 'Please log in to access this page.'
    
    # Initialize or load Fernet key
    global fernet
    fernet_key_path = os.path.join(app.config['KEYS_FOLDER'], 'server.key')
    
    if app.config['FERNET_KEY']:
        fernet = Fernet(app.config['FERNET_KEY'].encode())
    elif os.path.exists(fernet_key_path):
        with open(fernet_key_path, 'rb') as f:
            fernet = Fernet(f.read())
    else:
        # Generate new key for first run
        key = Fernet.generate_key()
        Config.init_app(app)  # Ensure directories exist
        with open(fernet_key_path, 'wb') as f:
            f.write(key)
        fernet = Fernet(key)
    
    # Initialize app-specific configs
    Config.init_app(app)
    
    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.contracts import contracts_bp
    from .routes.signing import signing_bp
    from .routes.admin import admin_bp
    from .routes.main import main_bp
    from .routes.mfa import mfa_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(contracts_bp, url_prefix='/contracts')
    app.register_blueprint(signing_bp, url_prefix='/signing')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(mfa_bp, url_prefix='/mfa')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app
