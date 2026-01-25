import psycopg2
from dotenv import load_dotenv
import os
import threading
import datetime
import math

from warmup_challenge import warmup_challenge as warmup_challenge
from teardown_challenge import teardown_challenge as teardown_challenge_backend

load_dotenv()


# Database connection parameters
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "exampledb")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "changeme")

POOL_MANAGER_LOGGING_DIR = os.getenv("POOL_MANAGER_LOGGING_DIR", "/var/log/pool_manager")

MONITORING_VPN_INTERFACE = os.getenv("MONITORING_VPN_INTERFACE", "ctf_monitoring")
MONITORING_DMZ_INTERFACE = os.getenv("MONITORING_DMZ_INTERFACE", "dmz_monitoring")

os.makedirs(POOL_MANAGER_LOGGING_DIR, exist_ok=True)


def get_db_connection():
    """
    Establish a connection to the PostgreSQL database.
    """
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn


class PoolManager:
    """
    PoolManager class to manage the hot pool of challenges.
    """

    def __init__(self, db_conn, minimal_pool_size=1, check_interval_seconds=10):
        self.running_warmups = {} # challenge_instance_id -> threading.Thread
        self.running_teardowns = {} # challenge_instance_id -> threading.Thread

        self.minimal_pool_size = minimal_pool_size
        self.check_interval_seconds = check_interval_seconds
        self.db_conn = db_conn

    def start(self):
        """
        Start the pool manager loop in a separate thread.
        """

        self.cleanup_leftover_from_crashed_processes()

        threading.Thread(target=self.pool_manager_loop, daemon=True).start()

    def pool_manager_loop(self):
        """
        Main loop of the pool manager to check and maintain the hot pool.
        """

        worker_threads = []

        while True:
            try:
                worker_threads.append(threading.Thread(target=self.check_and_maintain_pool, daemon=True))
                worker_threads.append(threading.Thread(target=self.teardown_expired_challenges, daemon=True))

                for thread in worker_threads:
                    thread.start()
                for thread in worker_threads:
                    thread.join()

            except Exception as e:
                print(f"Error in pool manager loop: {e}")
            finally:
                threading.Event().wait(self.check_interval_seconds)

    def check_and_maintain_pool(self):
        """
        Check the current pool sizes and maintain the hot pool.
        """

        with self.db_conn.cursor() as cursor:
            # Get all challenge templates
            cursor.execute("SELECT id FROM challenge_templates")
            challenge_template_ids = [row[0] for row in cursor.fetchall()]

        for challenge_template_id in challenge_template_ids:
            current_pool_size = self.get_current_pool_size(self.db_conn, challenge_template_id)
            target_pool_size = self.get_target_pool_size(self.db_conn, challenge_template_id)

            running_warmups_count = sum(1 for ct_id in self.running_warmups.values() if ct_id == challenge_template_id)
            total_effective_pool_size = current_pool_size + running_warmups_count

            if total_effective_pool_size < target_pool_size:
                warmups_needed = target_pool_size - total_effective_pool_size
                for _ in range(warmups_needed):
                    threading.Thread(target=self.managed_warmup, args=(challenge_template_id,), daemon=True).start()

            elif current_pool_size > target_pool_size:
                teardowns_needed = current_pool_size - target_pool_size
                with self.db_conn.cursor() as cursor:
                    cursor.execute("""
                        WITH candidates AS (
                            SELECT id
                            FROM challenges
                            WHERE challenge_template_id = %s
                            AND lifecycle_state = 'READY'
                            AND pre_assigned_user_id IS NULL
                            LIMIT %s
                            FOR UPDATE SKIP LOCKED
                        )
                        UPDATE challenges
                        SET lifecycle_state = 'TERMINATING'
                        WHERE id IN (SELECT id FROM candidates)
                        RETURNING id
                    """, (challenge_template_id, teardowns_needed))

                    challenge_instance_ids_to_teardown = [row[0] for row in cursor.fetchall()]

                for challenge_instance_id in challenge_instance_ids_to_teardown:
                    threading.Thread(target=self.managed_teardown, args=(challenge_template_id, challenge_instance_id,), daemon=True).start()

    def managed_teardown(self, challenge_template_id, challenge_instance_id):
        """
        Managed teardown process for a challenge instance.
        :param challenge_template_id:
        :param challenge_instance_id:
        """

        self.running_teardowns[threading.current_thread().ident] = challenge_template_id

        db_conn = get_db_connection()
        try:
            teardown_challenge_backend(challenge_instance_id, db_conn)
        finally:
            del self.running_teardowns[threading.current_thread().ident]
            db_conn.close()

    def managed_warmup(self, challenge_template_id):
        """
        Managed warmup process for a challenge template.
        :param challenge_template_id:
        """

        self.running_warmups[threading.current_thread().ident] = challenge_template_id

        db_conn = get_db_connection()
        try:
            warmup_challenge(None, challenge_template_id, db_conn, MONITORING_VPN_INTERFACE, MONITORING_DMZ_INTERFACE)
        finally:
            del self.running_warmups[threading.current_thread().ident]
            db_conn.close()

    def get_current_pool_size(self, db_conn, challenge_template_id):
        """
        Get the current pool size for a given challenge template.
        :param db_conn:
        :param challenge_template_id:
        :return pool_size:
        """

        with db_conn.cursor() as cursor:
            # Count finished or in progress warmups destined for the pool
            cursor.execute("""
                SELECT COUNT(*)
                FROM challenges
                WHERE challenge_template_id = %s
                AND lifecycle_state = 'READY'
                AND pre_assigned_user_id IS NULL
            """, (challenge_template_id,))

            current_pool_size = cursor.fetchone()[0]
            return current_pool_size

    def get_target_pool_size(self, db_conn, challenge_template_id):
        """
        Get the target pool size for a given challenge template.
        Interpolates between the closest past and future pool sizes based on the current time.
        :param db_conn:
        :param challenge_template_id:
        :return pool_size:
        """

        with db_conn.cursor() as cursor:
            current_time = datetime.datetime.now()

            # Get closest future pool size
            cursor.execute("""
                SELECT effective_time, size
                FROM pool_sizes
                WHERE challenge_template_id = %s
                AND effective_time > %s
                ORDER BY effective_time ASC
                LIMIT 1
            """, (challenge_template_id, current_time))

            future_size_row = cursor.fetchone()
            future_timestamp, future_pool_size = future_size_row if future_size_row else (None, 0)

            # Get closest past pool size
            cursor.execute("""
                SELECT effective_time, size
                FROM pool_sizes
                WHERE challenge_template_id = %s
                AND effective_time <= %s
                ORDER BY effective_time DESC
                LIMIT 1
            """, (challenge_template_id, current_time))

            past_size_row = cursor.fetchone()
            past_timestamp, past_pool_size = past_size_row if past_size_row else (None, 0)

            if past_timestamp is None and future_timestamp is None:
                return 0

            # If no past size found, use future size directly
            if past_timestamp is None:
                return future_pool_size

            # If no future size found, use past size directly
            if future_timestamp is None:
                return past_pool_size

            # Interpolate between past and future sizes
            total_duration = (future_timestamp - past_timestamp).total_seconds()
            elapsed_duration = (current_time - past_timestamp).total_seconds()
            interpolation_ratio = elapsed_duration / total_duration if total_duration > 0 else 0

            interpolated_size = past_pool_size + (future_pool_size - past_pool_size) * interpolation_ratio
            return math.ceil(interpolated_size) # Round up to ensure sufficient pool size

    def cleanup_leftover_from_crashed_processes(self):
        """
        Cleanup any leftover warmup or teardown processes from crashed PoolManager instances.
        """

        with self.db_conn.cursor() as cursor:
            # Find challenges stuck in PROVISIONING or TERMINATING state
            cursor.execute("""
                WITH orphaned_challenges AS (
                    SELECT id
                    FROM challenges
                    WHERE lifecycle_state IN ('PROVISIONING', 'TERMINATING')
                )
                UPDATE challenges
                SET lifecycle_state = 'TERMINATING'
                WHERE id IN (SELECT id FROM orphaned_challenges)
                RETURNING id
            """)

            orphaned_challenge_instances = [row[0] for row in cursor.fetchall()]

        for challenge_instance_id in orphaned_challenge_instances:
            db_conn = get_db_connection()
            threading.Thread(target=teardown_challenge_backend, args=(challenge_instance_id, db_conn,), daemon=True).start()

    def teardown_expired_challenges(self):
        """
        Teardown challenges that have been marked as EXPIRED but not yet cleaned up.
        """

        with self.db_conn.cursor() as cursor:
            # Find challenges stuck in TERMINATING state
            cursor.execute("""
                WITH expired_challenges AS (
                    SELECT id
                    FROM challenges
                    WHERE lifecycle_state = 'EXPIRED'
                )
                UPDATE challenges
                SET lifecycle_state = 'TERMINATING'
                WHERE id IN (SELECT id FROM expired_challenges)
                RETURNING id
            """)

            terminating_challenge_instances = [row[0] for row in cursor.fetchall()]

        teardown_threads = []
        for challenge_instance_id in terminating_challenge_instances:
            db_conn = get_db_connection()
            teardown_threads.append(threading.Thread(target=teardown_challenge_backend, args=(challenge_instance_id, db_conn,), daemon=True).start())
