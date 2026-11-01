"""init_db.py - SQLite database aur tables banata hai (app start par bhi apne aap ban jate hain).

Run:  python init_db.py
"""
from config import Settings
from database import Database


def main():
    settings = Settings.from_env()
    db = Database(settings.db_path)
    db.init_db()
    print(f"Database ready: {settings.db_path}")
    print("Tables: scans, findings")


if __name__ == "__main__":
    main()
