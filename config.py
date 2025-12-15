import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # ============ FLASK CONFIGURATION ============
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production-for-civiccare'

    # ============ DATABASE CONFIGURATION ============
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'data', 'issues.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ============ SESSION CONFIGURATION ============
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # ============ FILE UPLOAD CONFIGURATION ============
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {
        'png', 'jpg', 'jpeg', 'gif', 'bmp',  # Images
        'pdf', 'doc', 'docx', 'txt',  # Documents
        'mp4', 'avi', 'mov', 'mkv'  # Videos
    }

    # ============ SERVICE TYPES CONFIGURATION ============
    SERVICE_TYPES = {
        'road': {
            'name': 'Road & Transportation',
            'color': 'blue',
            'icon_class': 'fas fa-road',
            'badge_class': 'bg-primary'
        },
        'pipeline': {
            'name': 'Water Pipeline',
            'color': 'green',
            'icon_class': 'fas fa-faucet',
            'badge_class': 'bg-success'
        },
        'electricity': {
            'name': 'Electricity',
            'color': 'orange',
            'icon_class': 'fas fa-bolt',
            'badge_class': 'bg-warning'
        },
        'garbage': {
            'name': 'Garbage Collection',
            'color': 'purple',
            'icon_class': 'fas fa-trash',
            'badge_class': 'bg-purple'
        },
        'nuisance': {
            'name': 'Public Nuisance',
            'color': 'red',
            'icon_class': 'fas fa-exclamation-triangle',
            'badge_class': 'bg-danger'
        },
        'sewage': {
            'name': 'Sewage & Drainage',
            'color': 'brown',
            'icon_class': 'fas fa-water',
            'badge_class': 'bg-brown'
        },
        'other': {
            'name': 'Other Issues',
            'color': 'gray',
            'icon_class': 'fas fa-question-circle',
            'badge_class': 'bg-secondary'
        }
    }

    # ============ PRIORITY LEVELS CONFIGURATION ============
    PRIORITY_LEVELS = {
        'low': {
            'name': 'Low',
            'color': 'green',
            'badge_class': 'bg-success'
        },
        'medium': {
            'name': 'Medium',
            'color': 'yellow',
            'badge_class': 'bg-warning'
        },
        'high': {
            'name': 'High',
            'color': 'orange',
            'badge_class': 'bg-danger'
        },
        'critical': {
            'name': 'Critical',
            'color': 'red',
            'badge_class': 'bg-danger'
        }
    }

    # ============ ISSUE STATUSES CONFIGURATION ============
    ISSUE_STATUSES = {
        'pending': {
            'name': 'Pending',
            'color': 'gray',
            'badge_class': 'bg-secondary'
        },
        'in_progress': {
            'name': 'In Progress',
            'color': 'blue',
            'badge_class': 'bg-primary'
        },
        'on_hold': {
            'name': 'On Hold',
            'color': 'orange',
            'badge_class': 'bg-warning'
        },
        'done': {
            'name': 'Resolved',
            'color': 'green',
            'badge_class': 'bg-success'
        },
        'cancelled': {
            'name': 'Cancelled',
            'color': 'red',
            'badge_class': 'bg-danger'
        }
    }

    # ============ USER ROLES CONFIGURATION ============
    USER_ROLES = {
        'user': 'Citizen User',
        'moderator': 'Moderator',
        'admin': 'Administrator'
    }

    # ============ APPLICATION SETTINGS ============
    APP_NAME = 'CivicCare Platform'
    SUPPORT_EMAIL = 'support@civiccare.gov.in'
    ADMIN_EMAIL = 'admin@civiccare.gov.in'

    # ============ PAGINATION SETTINGS ============
    ISSUES_PER_PAGE = 20
    SOLUTIONS_PER_PAGE = 10
    USERS_PER_PAGE = 15


# Create necessary directories
def create_directories():
    """Create necessary directories for the application"""
    config = Config()
    directories = [
        config.UPLOAD_FOLDER,
        os.path.join(basedir, 'data'),
        os.path.join(basedir, 'backups'),
        os.path.join(basedir, 'static', 'uploads'),
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"Created directory: {directory}")


# Create directories when config is imported
create_directories()