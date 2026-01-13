import multiprocessing
import os

# Binding
bind = "0.0.0.0:8000"

# Workers
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = 'gthread'

# Logging
accesslog = "logs/gunicorn_access.log"
errorlog = "logs/gunicorn_error.log"
loglevel = "info"

# Process Naming
proc_name = "crypto_internal_tools"

# Timeout
timeout = 120

# Ensure logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')
