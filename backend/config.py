import os
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DATABASE_NAME = os.getenv("DATABASE_NAME", "vulnpilot_reports.db")

# 🔐 ADD THESE
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-key-change-this")
ALGORITHM = "HS256"