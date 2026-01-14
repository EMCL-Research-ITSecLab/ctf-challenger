import psycopg2
from dotenv import load_dotenv
import os
import threading

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


# TODO: Implement PoolManager class and its methods here



