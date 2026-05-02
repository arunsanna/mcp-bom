"""Server reads only LITERAL env vars for its own configuration. Tier 1."""
import os

API_KEY = os.environ.get("NOTION_API_KEY")
DB_URL = os.getenv("DATABASE_URL", "sqlite:///")
TOKEN = os.environ["GITHUB_TOKEN"]


def get_config():
    return {"api_key": API_KEY, "db_url": DB_URL, "token": TOKEN}
