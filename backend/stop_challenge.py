from DatabaseClasses import *
from proxmox_api_calls import *
import subprocess
import os
import time
import requests
import urllib3
from tenacity import retry, stop_after_attempt, wait_fixed
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

CHALLENGES_ROOT_SUBNET = os.getenv("CHALLENGES_ROOT_SUBNET", "10.128.0.0")
CHALLENGES_ROOT_SUBNET_MASK = os.getenv("CHALLENGES_ROOT_SUBNET_MASK", "255.128.0.0")
CHALLENGES_ROOT_SUBNET_MASK_INT = sum(bin(int(x)).count('1') for x in CHALLENGES_ROOT_SUBNET_MASK.split('.'))
CHALLENGES_ROOT_SUBNET_CIDR = f"{CHALLENGES_ROOT_SUBNET}/{CHALLENGES_ROOT_SUBNET_MASK_INT}"


def stop_challenge(user_id, db_conn):
    """
    Stop a challenge for a user.
    """

    with db_conn:
        user_static_ip, challenge_id = get_user_static_ip_and_challenge_id(user_id, db_conn)
        block_user_access_to_vm_subnet(user_static_ip)
        mark_challenge_expired(challenge_id, db_conn)


def get_user_static_ip_and_challenge_id(user_id, db_conn):
    """
    Get the running challenge ID for a user.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("""
            SELECT vpn_static_ip, running_challenge
            FROM users
            WHERE id = %s
        """, (user_id,))

        result = cursor.fetchone()
        if not result:
            raise Exception(f"No running challenge found for user ID {user_id}")

        return result[0], result[1]


def mark_challenge_expired(challenge_id, db_conn):
    """
    Mark the challenge as expired in the database.
    """
    with db_conn.cursor() as cursor:
        cursor.execute("""
            UPDATE challenges
            SET lifecycle_state = 'EXPIRED'
            WHERE id = %s
        """, (challenge_id,))


def block_user_access_to_vm_subnet(user_static_ip):
    """
    Block user access to the VM subnet by updating firewall rules.
    """

    # Block traffic from user IP to VM subnet
    subprocess.run([
        "iptables", "-P", "FORWARD", "-s", user_static_ip, "-d", CHALLENGES_ROOT_SUBNET_CIDR, "-j", "DROP"
    ], check=False, capture_output=True)

    # Block traffic from VM subnet to user IP
    subprocess.run([
        "iptables", "-P", "FORWARD", "-s", CHALLENGES_ROOT_SUBNET_CIDR, "-d", user_static_ip, "-j", "DROP"
    ], check=False, capture_output=True)
