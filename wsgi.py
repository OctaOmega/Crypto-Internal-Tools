from app import create_app
from werkzeug.middleware.proxy_fix import ProxyFix

app = create_app()

# Apply ProxyFix for Nginx header forwarding (X-Forwarded-For, X-Forwarded-Proto)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

if __name__ == "__main__":
    app.run()
