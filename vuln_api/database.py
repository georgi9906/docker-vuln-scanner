import os
import psycopg2
from dotenv import load_dotenv
from pathlib import Path

env_path = Path("/home/kali/Desktop/vuln_api/credentials.env")
load_dotenv(dotenv_path=env_path)

print("Loaded DB_USER:", os.getenv("DB_USER"))  # Debug print

def get_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT", 5432)
    )
