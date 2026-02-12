import os
import signal
import fcntl

from dotenv import load_dotenv
from stop_challenge import stop_challenge
import threading
from teardown_challenge import teardown_challenge
load_dotenv()

DATABASE_HOST = os.getenv("DB_HOST", "10.0.0.102")
DATABASE_PORT = os.getenv("DB_PORT", "5432")
DATABASE_USER = os.getenv("DB_USER", "postgres")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
DATABASE_NAME = os.getenv("DB_NAME", "ctf_challenger")

CLEANUP_COMPLETE_FILE_PATH = "/var/lock/cleanup_complete.lock"
if not os.path.exists(CLEANUP_COMPLETE_FILE_PATH):
    with open(CLEANUP_COMPLETE_FILE_PATH, 'w') as f:
        pass

def cleanup_remaining_challenges():
    """
    Remove all challenges from the database.
    """
    signal_cleanup_not_complete()

    db_conn = wait_for_db_connection()

    user_ids = fetch_user_ids(db_conn)
    stop_running_challenges(user_ids)

    remaining_challenge_ids = fetch_remaining_challenge_ids(db_conn)
    teardown_remaining_challenges(remaining_challenge_ids)

    signal_cleanup_complete()


def signal_cleanup_not_complete():
    """
    Signal that the cleanup process is not complete by acquiring a lock on a file.
    """

    with open(CLEANUP_COMPLETE_FILE_PATH, 'w') as f:
        fcntl.flock(f, fcntl.LOCK_EX)



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

    threads = []

    for user_id in user_ids:
        thread = threading.Thread(target=stop_challenge, args=(user_id,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def fetch_remaining_challenge_ids(db_conn):
    """
    Fetch all remaining challenge IDs from the database.
    """
    challenge_ids = []
    with db_conn.cursor() as cursor:
        cursor.execute("SELECT id FROM challenges WHERE lifecycle_state != 'EXPIRED'")
        challenge_ids = [row[0] for row in cursor.fetchall()]

    return challenge_ids


def teardown_remaining_challenges(challenge_ids):
    """
    Teardown all remaining challenges.
    """

    threads = []

    for challenge_id in challenge_ids:
        thread = threading.Thread(target=teardown_challenge, args=(challenge_id,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


def signal_cleanup_complete():
    """
    Signal that the cleanup process is complete by releasing the lock on the file.
    """
    with open(CLEANUP_COMPLETE_FILE_PATH, 'w') as f:
        fcntl.flock(f, fcntl.LOCK_UN)


if __name__ == "__main__":
    cleanup_remaining_challenges()
