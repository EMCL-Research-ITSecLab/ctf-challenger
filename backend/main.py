from flask import Flask, request, send_file, redirect
import psycopg2
from dotenv import load_dotenv
from cloud_init_ip_pool import ip_pool
import os

from launch_challenge import launch_challenge as launch_challenge_backend
from stop_challenge import stop_challenge as stop_challenge_backend
from import_machine_templates import import_machine_templates as import_machine_template_backend
from delete_machine_templates import delete_machine_templates as delete_machine_template_backend
from get_user_config import get_user_config as get_user_config_backend
from delete_user_config import delete_user_config as delete_user_config_backend

load_dotenv()

app = Flask(__name__)

# Database connection parameters
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "exampledb")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "changeme")

BACKEND_HOST = os.getenv("BACKEND_HOST", "10.0.0.1")
BACKEND_PORT = os.getenv("BACKEND_PORT", "8000")

BACKEND_LOGGING_DIR = os.getenv("BACKEND_LOGGING_DIR", "/var/log/backend")

BACKEND_CERTIFICATE_FILE = os.getenv("BACKEND_CERTIFICATE_FILE", "/root/ctf-challenger/backend.crt")
BACKEND_CERTIFICATE_KEY_FILE = os.getenv("BACKEND_CERTIFICATE_KEY_FILE", "/root/ctf-challenger/backend.key")

BACKEND_AUTHENTICATION_TOKEN = os.getenv("BACKEND_AUTHENTICATION_TOKEN")

MONITORING_VPN_INTERFACE = os.getenv("MONITORING_VPN_INTERFACE", "ctf_monitoring")
MONITORING_DMZ_INTERFACE = os.getenv("MONITORING_DMZ_INTERFACE", "dmz_monitoring")

os.makedirs(BACKEND_LOGGING_DIR, exist_ok=True)


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



@app.before_request
def before_request():
    """
    This function runs before each request to the Flask app.
    First, all http requests are redirected to https.
    It checks if the user is authorized based on the authentication token.
    """

    if not request.is_secure:
        return redirect(f"https://{request.host}{request.path}", code=301)

    authentication_token = request.headers.get('Authentication-Token')

    if not authentication_token or not authentication_token == BACKEND_AUTHENTICATION_TOKEN:
        print("Unauthorized access attempt", flush=True)
        return {"error": "Unauthorized", "success": False}, 401


@app.route('/launch-challenge', methods=['POST'])
def launch_challenge():
    try:
        db_conn = get_db_connection()

        try:
            data = request.json
            challenge_template_id = data['challenge_template_id']
            user_id = data['user_id']
            _ = int(challenge_template_id)
            _ = int(user_id)
        except Exception as e:
            print("Invalid input data", e, flush=True)
            return {"error": "Invalid input data", "success": False}, 500

        try:
            accessible_networks = launch_challenge_backend(challenge_template_id, user_id, db_conn, ip_pool, MONITORING_VPN_INTERFACE, MONITORING_DMZ_INTERFACE)
        except Exception as e:
            print("Error launching challenge", e, flush=True)
            return {"error": str(e), "success": False}, 500

        return {"message": "Challenge launched", "success": True, "entrypoints": accessible_networks}, 200

    except Exception as e:
        print("Database connection error", e, flush=True)
        return {"error": "Database connection error", "success": False}, 500

    finally:
        if 'db_conn' in locals():
            db_conn.close()


@app.route('/stop-challenge', methods=['POST'])
def stop_challenge():
    try:
        db_conn = get_db_connection()

        try:
            data = request.json
            user_id = data['user_id']
            _ = int(user_id)
        except Exception as e:
            print("Invalid input data", e, flush=True)
            return {"error": "Invalid input data", "success": False}, 500

        try:
            stop_challenge_backend(user_id, db_conn)
        except Exception as e:
            print("Error stopping challenge", e, flush=True)
            return {"error": str(e), "success": False}, 500

        return {"message": "Challenge stopped", "success": True}, 200

    except Exception as e:
        print("Database connection error", e, flush=True)
        return {"error": "Database connection error", "success": False}, 500

    finally:
        if 'db_conn' in locals():
            db_conn.close()


@app.route('/import-machine-templates', methods=['POST'])
def import_machine_template():
    try:
        db_conn = get_db_connection()

        try:
            data = request.json
            challenge_template_id = data['challenge_template_id']
            _ = int(challenge_template_id)
        except Exception as e:
            print("Invalid input data", e, flush=True)
            return {"error": "Invalid input data", "success": False}, 500

        try:
            import_machine_template_backend(challenge_template_id, db_conn, ip_pool)
        except Exception as e:
            print("Error importing machine templates", e, flush=True)
            return {"error": str(e), "success": False}, 500

        return {"message": "Machine template imported", "success": True}, 200

    except Exception as e:
        print("Database connection error", e, flush=True)
        return {"error": "Database connection error", "success": False}, 500

    finally:
        if 'db_conn' in locals():
            db_conn.close()


@app.route('/delete-machine-templates', methods=['POST'])
def delete_machine_templates():
    try:
        db_conn = get_db_connection()

        try:
            data = request.json
            challenge_id = data['challenge_id']
            _ = int(challenge_id)
        except Exception as e:
            print("Invalid input data", e, flush=True)
            return {"error": "Invalid input data", "success": False}, 500

        try:
            delete_machine_template_backend(challenge_id, db_conn)
        except Exception as e:
            print("Error deleting machine templates", e, flush=True)
            return {"error": str(e), "success": False}, 500

        return {"message": "Machine templates deleted", "success": True}, 200

    except Exception as e:
        print("Database connection error", e, flush=True)
        return {"error": "Database connection error", "success": False}, 500

    finally:
        if 'db_conn' in locals():
            db_conn.close()


@app.route('/get-user-config', methods=['POST'])
def get_user_config():
    try:
        db_conn = get_db_connection()

        try:
            data = request.json
            user_id = data['user_id']
            _ = int(user_id)
        except Exception as e:
            print("Invalid input data", e, flush=True)
            return {"error": "Invalid input data", "success": False}, 500

        try:
            user_config_path = get_user_config_backend(user_id, db_conn)
        except Exception as e:
            print("Error in getting user config", e, flush=True)
            return {"error": str(e), "success": False}, 500

        return send_file(user_config_path, as_attachment=True)

    except Exception as e:
        print("Database connection error", e, flush=True)
        return {"error": "Database connection error", "success": False}, 500

    finally:
        if 'db_conn' in locals():
            db_conn.close()


@app.route('/delete-user-config', methods=['POST'])
def delete_user_config():
    data = request.json
    user_id = data['user_id']

    delete_user_config_backend(user_id)
    return {"message": "User config deleted", "success": True}, 200
    

app.run(host=BACKEND_HOST, port=int(BACKEND_PORT), ssl_context=(BACKEND_CERTIFICATE_FILE, BACKEND_CERTIFICATE_KEY_FILE))
