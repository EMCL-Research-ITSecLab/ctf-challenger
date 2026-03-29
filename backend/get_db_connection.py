from dotenv import load_dotenv
import psycopg2
import os
import functools

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


def run_with_db_connection(func):

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            db_conn = get_db_connection()

            return func(*args, **kwargs, db_conn=db_conn)
        finally:
            db_conn.close()

    return wrapper