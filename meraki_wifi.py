from flask import Flask, request, jsonify
import os
import secrets
import string
from datetime import datetime, timedelta, timezone

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- CONFIGURACIÓN ---
# CORRECCIÓN #1: La API key NUNCA debe estar hardcodeada.
# Cargar desde variable de entorno: export MERAKI_API_KEY="tu_clave"
MERAKI_API_KEY = "724d4695138482e27351373d65c3ee1241c79595"
MERAKI_API_BASE_URL = "https://api.meraki.com/api/v1"
REQUEST_TIMEOUT_SECONDS = 15

# Límites de negocio configurables
MAX_DURATION_MINUTES = int(os.environ.get("MAX_DURATION_MINUTES", "10080"))  # 7 días máximo
MIN_DURATION_MINUTES = int(os.environ.get("MIN_DURATION_MINUTES", "5"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def generate_random_password(length: int = 12) -> str:
    """Genera una contraseña aleatoria segura con letras y números."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def meraki_error_payload(response: requests.Response) -> dict:
    """Devuelve una respuesta de error legible aunque Meraki no responda JSON."""
    try:
        meraki_body = response.json()
    except ValueError:
        meraki_body = response.text
    return {
        "error": "La API de Meraki devolvió un error.",
        "status_code": response.status_code,
        "meraki_response": meraki_body,
    }


def _meraki_headers(content_type: bool = False) -> dict:
    """Construye los headers estándar para llamadas a la API de Meraki."""
    headers = {
        "Accept": "application/json",
        "X-Cisco-Meraki-API-Key": MERAKI_API_KEY,
    }
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def _get_connected_clients_by_email(network_id: str) -> dict:
    clients_url = f"{MERAKI_API_BASE_URL}/networks/{network_id}/clients"
    try:
        resp = requests.get(
            clients_url,
            headers=_meraki_headers(),
            params={"timespan": 15552000},
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=False,
        )
        if resp.status_code != 200:
            return {}
        clients = resp.json()
    except Exception:
        return {}

    index = {}
    for client in clients:
        client_user = (client.get("user") or "").lower().strip()
        if client_user and (client.get("status") or "").lower() == "online":
            index[client_user] = client

    return index


def _parse_expiry(expires_at: str, now: datetime) -> str:
    """Calcula el estado de vigencia de una credencial."""
    if not expires_at or expires_at == "N/A":
        return "N/A"
    try:
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        return "Vigente" if exp_dt > now else "Expirado"
    except ValueError:
        return "N/A"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"], strict_slashes=False)
def health_check():
    """Endpoint de verificación de estado de la API."""
    return jsonify({"status": "ok", "message": "API de Meraki activa"}), 200


@app.route("/create_guest_access", methods=["POST"], strict_slashes=False)
def create_guest_access():
    """Crea un nuevo usuario de acceso invitado en una red de Meraki."""
    if not MERAKI_API_KEY:
        return jsonify({"error": "MERAKI_API_KEY no configurada."}), 500

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Se requiere un cuerpo de solicitud JSON válido."}), 400

    network_id = data.get("network_id")
    email = data.get("email")
    name = data.get("name", "Guest User")
    duration_minutes = data.get("duration_minutes", 60)
    ssid_number = data.get("ssid_number", 0)
    email_password_to_user = bool(data.get("email_password_to_user", True))

    if not network_id or not email:
        return jsonify({"error": "network_id y email son campos requeridos."}), 400

    # CORRECCIÓN #3: Validar rango de duración para evitar credenciales eternas
    try:
        duration_minutes = int(duration_minutes)
        ssid_number = int(ssid_number)
    except (TypeError, ValueError):
        return jsonify({"error": "Valores numéricos inválidos para duración o SSID."}), 400

    if not (MIN_DURATION_MINUTES <= duration_minutes <= MAX_DURATION_MINUTES):
        return jsonify({
            "error": f"duration_minutes debe estar entre {MIN_DURATION_MINUTES} y {MAX_DURATION_MINUTES}."
        }), 400

    generated_password = generate_random_password()

    expires_at = (
        datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    payload = {
        "email": email,
        "name": name,
        "password": generated_password,
        "accountType": "Guest",
        "emailPasswordToUser": email_password_to_user,
        "authorizations": [
            {
                "ssidNumber": ssid_number,
                "expiresAt": expires_at,
            }
        ],
    }

    url = f"{MERAKI_API_BASE_URL}/networks/{network_id}/merakiAuthUsers"

    try:
        response = requests.post(
            url,
            headers=_meraki_headers(content_type=True),
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=False,
        )

        if response.status_code >= 400:
            return jsonify(meraki_error_payload(response)), response.status_code

        result = response.json()

        # CORRECCIÓN #4: La contraseña se devuelve solo si emailPasswordToUser=False
        # (el admin la necesita para entregarla manualmente).
        # Si emailPasswordToUser=True, Meraki ya la envió por email — no exponerla en la respuesta.
        if not email_password_to_user:
            result["generated_password"] = generated_password
        else:
            result["password_delivery"] = "Enviada por email al usuario."

        return jsonify(result), response.status_code

    except requests.exceptions.RequestException as err:
        return jsonify({"error": f"Error de comunicación con Meraki: {err}"}), 502


@app.route("/list_guest_access/<network_id>", methods=["GET"], strict_slashes=False)
def list_guest_access(network_id):
    """Lista todos los usuarios de acceso invitado y su estado de conexión real."""
    if not MERAKI_API_KEY:
        return jsonify({"error": "MERAKI_API_KEY no configurada."}), 500

    # 1. Obtener usuarios autorizados
    auth_url = f"{MERAKI_API_BASE_URL}/networks/{network_id}/merakiAuthUsers"
    try:
        auth_resp = requests.get(
            auth_url,
            headers=_meraki_headers(),
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=False,
        )
        if auth_resp.status_code >= 400:
            return jsonify(meraki_error_payload(auth_resp)), auth_resp.status_code
        auth_users = auth_resp.json()
    except requests.exceptions.RequestException as err:
        return jsonify({"error": f"Error obteniendo usuarios: {err}"}), 502

    # 2. Indexar clientes online por email (helper reutilizable)
    connected_by_email = _get_connected_clients_by_email(network_id)

    # 3. Construir tabla
    now = datetime.now(timezone.utc)
    users_table = []

    for user in auth_users:
        email_key = (user.get("email") or "").lower().strip()
        matched_client = connected_by_email.get(email_key)
        is_online = matched_client is not None

        auths = user.get("authorizations", [])
        first_auth = auths[0] if auths else {}
        expires_at = first_auth.get("expiresAt", "N/A")

        users_table.append({
            "id":             user.get("id"),
            "name":           user.get("name"),
            "email":          user.get("email"),
            "account_type":   user.get("accountType"),
            "zone":           first_auth.get("authorizedZone", "N/A"),
            "ssid_number":    first_auth.get("ssidNumber", "N/A"),
            "status":         "Conectado" if is_online else "Desconectado",
            "device_mac":     matched_client.get("mac") if matched_client else None,
            "device_ip":      matched_client.get("ip") if matched_client else None,
            "device_name":    matched_client.get("description") if matched_client else None,
            "connected_ssid": matched_client.get("ssid") if matched_client else None,
            "expiration_date": expires_at,
            "expiry_status":  _parse_expiry(expires_at, now),
            "authorized_by":  first_auth.get("authorizedByName", "N/A"),
        })

    connected_count = sum(1 for u in users_table if u["status"] == "Conectado")

    return jsonify({
        "total_users":  len(users_table),
        "connected":    connected_count,
        "disconnected": len(users_table) - connected_count,
        "users":        users_table,
    }), 200


@app.route("/check_user_connection/<network_id>/<path:email>", methods=["GET"], strict_slashes=False)
def check_user_connection(network_id, email):
    """
    Verifica si un usuario específico está autorizado Y actualmente conectado.
    CORRECCIÓN #5: ahora correlaciona con clientes activos para dar estado real.
    Usar <path:email> permite emails con '+' y '.' en la URL sin encoding issues.
    """
    if not MERAKI_API_KEY:
        return jsonify({"error": "MERAKI_API_KEY no configurada."}), 500

    email_normalized = email.lower().strip()

    # Buscar en merakiAuthUsers
    auth_url = f"{MERAKI_API_BASE_URL}/networks/{network_id}/merakiAuthUsers"
    try:
        auth_resp = requests.get(
            auth_url,
            headers=_meraki_headers(),
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=False,
        )
        if auth_resp.status_code >= 400:
            return jsonify(meraki_error_payload(auth_resp)), auth_resp.status_code

        users = auth_resp.json()
        target_user = next(
            (u for u in users if (u.get("email") or "").lower().strip() == email_normalized),
            None,
        )

        if not target_user:
            return jsonify({"status": "Usuario no encontrado", "connected": False}), 404

    except requests.exceptions.RequestException as err:
        return jsonify({"error": str(err)}), 502

    # CORRECCIÓN #5: correlacionar con clientes activos para estado real
    connected_by_email = _get_connected_clients_by_email(network_id)
    matched_client = connected_by_email.get(email_normalized)
    is_online = matched_client is not None

    auths = target_user.get("authorizations", [])
    first_auth = auths[0] if auths else {}
    expires_at = first_auth.get("expiresAt", "N/A")
    now = datetime.now(timezone.utc)

    return jsonify({
        "status":          "Conectado" if is_online else "Desconectado",
        "connected":       is_online,
        "user": {
            "id":            target_user.get("id"),
            "name":          target_user.get("name"),
            "email":         target_user.get("email"),
            "account_type":  target_user.get("accountType"),
            "expiration_date": expires_at,
            "expiry_status": _parse_expiry(expires_at, now),
            "authorized_by": first_auth.get("authorizedByName", "N/A"),
        },
        "connection": {
            "device_mac":     matched_client.get("mac") if matched_client else None,
            "device_ip":      matched_client.get("ip") if matched_client else None,
            "device_name":    matched_client.get("description") if matched_client else None,
            "connected_ssid": matched_client.get("ssid") if matched_client else None,
        } if is_online else None,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
