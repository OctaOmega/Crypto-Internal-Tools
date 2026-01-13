from app import create_app, db
from app.models import CourseModule, FileAsset

app = create_app()
with app.app_context():
    module = CourseModule.query.filter_by(title='TSET').first()
    if module:
        print(f"Module: {module.title}, ID: {module.id}")
        print(f"Type: {module.type}")
        print(f"File ID: {module.file_id}")
        if module.file_id:
            asset = FileAsset.query.get(module.file_id)
            if asset:
                print(f"File Asset: {asset.filename}, Path: {asset.storage_path}")
            else:
                print("File Asset not found in DB even though ID exists.")
        else:
            print("No file_id associated.")
    else:
        print("Module 'TSET' not found.")
