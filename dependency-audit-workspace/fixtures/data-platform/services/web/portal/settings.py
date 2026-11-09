import yaml
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = "dev-only"
INSTALLED_APPS = ["django.contrib.contenttypes", "django.contrib.auth", "rest_framework"]
FEATURES = yaml.load(open(BASE_DIR / "features.yml"), Loader=yaml.Loader)
