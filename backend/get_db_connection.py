from dotenv import load_dotenv
import psycopg2
import os
from contextlib import contextmanager

load_dotenv()

# Database connection parameters
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "exampledb")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "changeme")

def get_db_connection():
    """
    Establish a connection to the PostgreSQL database.
    """
    print("[DB] Opening new database connection")


    db_conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    db_conn.autocommit = True
    return db_conn


@contextmanager
def db_connection_context():
    """
    Provide a managed PostgreSQL connection and always close it.
    """
    db_conn = get_db_connection()
    try:
        yield db_conn
    finally:
        db_conn.close()
