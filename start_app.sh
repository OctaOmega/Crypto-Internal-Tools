#!/bin/bash

# Navigate to app directory
cd /home/wsl2user/crypto_app

# Run Gunicorn in background (daemon mode)
/home/wsl2user/crypto_app/venv/bin/gunicorn -c /home/wsl2user/crypto_app/gunicorn_config.py --daemon wsgi:app

echo "Gunicorn started in background. Check logs at /var/log/crypto_app/"
