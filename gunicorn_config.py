import multiprocessing
import os

# Binding
bind = "0.0.0.0:8000"

# Path configuration
pythonpath = "/home/wsl2user/crypto_app"

# Workers
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = 'gthread'

# Logging
accesslog = "/var/log/crypto_app/access.log"
errorlog = "/var/log/crypto_app/error.log"
loglevel = "info"

# Process Naming
proc_name = "crypto_internal_tools"

# Timeout
timeout = 120
