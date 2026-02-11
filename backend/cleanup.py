import os
from dotenv import load_dotenv
from stop_challenge import stop_challenge

load_dotenv()

DATABASE_HOST = os.getenv("DB_HOST", "10.0.0.102")
DATABASE_PORT = os.getenv("DB_PORT", "5432")
DATABASE_USER = os.getenv("DB_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
DATABASE_NAME = os.getenv("DB_NAME", "ctf_challenger")


def cleanup_remaining_challenges():
    """
    Remove all challenges from the database.
    """
    db_conn = wait_for_db_connection()

    user_ids = fetch_user_ids(db_conn)

    stop_running_challenges(user_ids)


def wait_for_db_connection():
    """
    Wait for the database connection to be available.
    """
    import psycopg2

    db_conn = None
    while not db_conn:
        try:
            db_conn = psycopg2.connect(
                host=DATABASE_HOST,
                port=DATABASE_PORT,
                user=DATABASE_USER,
                password=DATABASE_PASSWORD,
                dbname=DATABASE_NAME
            )

        except Exception:
            pass

    return db_conn


def fetch_user_ids(db_conn):
    """
    Fetch all running challenges from the database.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM users WHERE running_challenge IS NOT NULL")
        user_ids = [row[0] for row in cursor.fetchall()]

    return user_ids


def stop_running_challenges( user_ids):
    """
    Stop all running challenges for the specified user IDs.
    """
    for user_id in user_ids:
        stop_challenge(user_id)


if __name__ == "__main__":
    cleanup_remaining_challenges()
