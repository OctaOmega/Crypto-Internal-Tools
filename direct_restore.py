import sqlite3
import os

db_path = os.path.join("instance", "app.db")
print(f"Connecting to database at {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check current status
    cursor.execute("SELECT id, name, email, role FROM user WHERE id = 1")
    user = cursor.fetchone()
    print(f"User ID 1 before update: {user}")
    
    # Update
    cursor.execute("UPDATE user SET role = 'admin' WHERE id = 1")
    conn.commit()
    
    # Verify
    cursor.execute("SELECT id, name, email, role FROM user WHERE id = 1")
    user = cursor.fetchone()
    print(f"User ID 1 after update: {user}")
    
    conn.close()
    print("Database updated successfully.")
except Exception as e:
    print(f"Error: {e}")
