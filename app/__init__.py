from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_mail import Mail
from config import Config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
login.login_view = 'auth.login'
login.login_message = 'Please log in to access this page.'
mail = Mail()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login.init_app(app)
    mail.init_app(app)

    @app.context_processor
    def inject_unread_count():
        if current_user.is_authenticated:
            from app.models import Notification
            count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
            return dict(unread_count=count)
        return dict(unread_count=0)

    # Register Blueprints
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.staff import bp as staff_bp
    app.register_blueprint(staff_bp)

    from app.manager import bp as manager_bp
    app.register_blueprint(manager_bp, url_prefix='/manager')
    
    from app.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Template Filters
    @app.template_filter('youtube_embed')
    def youtube_embed_filter(url):
        if not url:
            return ''
        if 'youtube.com/watch?v=' in url:
            return url.replace('youtube.com/watch?v=', 'youtube.com/embed/')
        if 'youtu.be/' in url:
            return url.replace('youtu.be/', 'youtube.com/embed/')
        return url

    with app.app_context():
        # Temporary: Ensure tables/columns exist (this isn't a perfect migration but works for new tables/simple adds in dev)
        # Note: SQLAlchemy create_all ONLY creates missing tables, it does NOT alter existing ones.
        db.create_all()
        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE notification ADD COLUMN link VARCHAR(256)"))
        except Exception:
            pass # Column likely exists
            
        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE course ADD COLUMN due_date DATETIME"))
        except Exception:
            pass 
            
        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE enrollment ADD COLUMN completed_at DATETIME"))
        except Exception:
            pass 
            
        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE enrollment ADD COLUMN total_time_seconds INTEGER DEFAULT 0"))
        except Exception:
            pass 
            
        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE enrollment ADD COLUMN started_at DATETIME"))
        except Exception:
            pass 
            
        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE user ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"))
        except Exception:
            pass

        try:
             with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE user ADD COLUMN locked_until DATETIME"))
        except Exception:
            pass 

    from app import cli
    cli.register(app)

    # Logging Configuration
    if not app.debug or True: # Always log for this internal tool requirement
        import logging
        from logging.handlers import RotatingFileHandler
        import os
        
        if not os.path.exists('logs'):
            os.mkdir('logs')
            
        file_handler = RotatingFileHandler('logs/internal_tools.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Crypto Internal Tools startup')

    return app

from app import models
