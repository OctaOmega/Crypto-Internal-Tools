from app import create_app, db
from app.models import NewsItem

app = create_app()
with app.app_context():
    print("Creating database tables...")
    db.create_all()
    print("Tables created.")
