from app import create_app, db
from app.models import CourseModule, FileAsset
import os

app = create_app()
with app.app_context():
    module = CourseModule.query.get(6)
    if module:
        print(f"Module: {module.title}, ID: {module.id}")
        print(f"Type: {module.type}")
        print(f"File ID: {module.file_id}")
        if module.file:
            asset = module.file
            print(f"File Asset ID: {asset.id}")
            print(f"Filename: {asset.filename}")
            print(f"Storage Path: {asset.storage_path}")
            print(f"Mime Type: {asset.mime_type}")
            
            # Check physical file
            full_path = os.path.join(app.root_path, 'static', asset.storage_path)
            print(f"Checking full path: {full_path}")
            if os.path.exists(full_path):
                print(f"File exists. Size: {os.path.getsize(full_path)} bytes")
            else:
                print("File DOES NOT EXIST on disk.")
        else:
            print("No file relation found on module (module.file is None)")
    else:
        print("Module 6 not found.")
