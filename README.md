# Internal Staff Training LMS

A Flask-based Learning Management System (LMS-lite) with RBAC, progress tracking, and reporting.

## Features
- **Role-Based Access**: Managers vs Staff.
- **Course Management**: CRUD for courses and modules (PDF, Video, Rich Text).
- **Progress Tracking**: Time tracking via heartbeat API.
- **Reporting**: Excel export of enrollment data.
- **Notifications**: In-app notifications for users.
- **Internal Tools**: Quick links to internal utilities.

## Setup

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Configuration**:
    - `.env` file is already set up with defaults.
    - Database is SQLite (`app.db`).

3.  **Initialize Database**:
    ```bash
    flask db upgrade
    ```

4.  **Seed Data**:
    ```bash
    python seed_data.py
    ```
    (This will create demo users and courses)

5.  **Run Application**:
    ```bash
    flask run
    ```
    Access at `http://localhost:5000`

## Demo Credentials

| Role    | Email                | Password |
|---------|----------------------|----------|
| Manager | `alice@example.com`  | `password` |
| Manager | `bob@example.com`    | `password` |
| Staff   | `staff1@example.com` | `password` |
| Staff   | `staff10@example.com`| `password` |
| Admin   | `admin@example.com`| `password` |

## Project Structure
- `app/`: Main application package.
    - `models.py`: Database models.
    - `auth/`: Authentication blueprint.
    - `manager/`: Manager workflow blueprint.
    - `staff/`: Staff/Learner workflow blueprint.
    - `api/`: AJAX endpoints (heartbeat).
    - `templates/`: Jinja2 templates.
    - `static/`: CSS/JS assets.
- `migrations/`: Alembic database migrations.
- `config.py`: Configuration settings.
- `run.py`: Application entry point.
