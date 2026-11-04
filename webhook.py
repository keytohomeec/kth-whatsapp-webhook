#!/usr/bin/env python3
"""
Key To Home — Receptor de webhook de WhatsApp Cloud API (variante hosting).

Mismo alcance que la versión local (ver ../webhook.py):
  - Responde la verificación GET que Meta hace al registrar el webhook.
  - Recibe eventos POST de WhatsApp y los guarda, estructurados y SIN
    procesar, en una cola en disco (queue/). Nada más.
  - NO responde clientes, NO envía mensajes, NO llama a la Graph API.
  - Cada evento guardado también se imprime en el log del servicio
    (stdout), para que ningún evento se pierda si el disco efímero del
    hosting se reinicia antes de que la vigilancia lo recoja.

Diferencias para hosting (Render):
  - Escucha en 0.0.0.0:$PORT (el hosting asigna el puerto por entorno).
  - Secretos por variables de entorno, con respaldo a archivos locales:
      KTH_WA_VERIFY_TOKEN  (token de verificación del webhook)
      KTH_WA_APP_SECRET    (App Secret de Meta; habilita la verificación
                            de firma X-Hub-Signature-256 cuando exista)
  - Sin dependencias: solo librería estándar de Python 3.
"""

import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

BASE = Path(__file__).resolve().parent
SECRETS = BASE / "secrets"
QUEUE = Path(os.environ.get("KTH_WA_QUEUE_DIR", str(BASE / "queue")))
HOST = os.environ.get("KTH_WA_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", os.environ.get("KTH_WA_PORT", "10000")))


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[{ts}] {msg}", flush=True)


def read_secret(env_name: str, file_name: str):
    value = os.environ.get(env_name)
    if value:
        return value.strip()
    p = SECRETS / file_name
    if p.exists():
        value = p.read_text(encoding="utf-8").strip()
        return value or None
    return None


def get_verify_token():
    return read_secret("KTH_WA_VERIFY_TOKEN", "verify_token.txt")


def verify_signature(raw_body: bytes, header_value):
    """Devuelve True/False si hay app secret; None si aún no está configurado."""
    app_secret = read_secret("KTH_WA_APP_SECRET", "app_secret.txt")
    if app_secret is None:
        return None  # hueco pendiente hasta que exista el App Secret
    if not header_value or not header_value.startswith("sha256="):
        return False
    expected = hmac.new(
        app_secret.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header_value.split("=", 1)[1].strip())


def extract_messages(payload):
    """Extrae un resumen de mensajes de un payload de WhatsApp, sin procesarlos."""
    found = []
    if not isinstance(payload, dict):
        return found
    for entry in payload.get("entry", []) or []:
        for change in entry.get("changes", []) or []:
            value = change.get("value", {}) or {}
            for message in value.get("messages", []) or []:
                found.append(
                    {
                        "wamid": message.get("id"),
                        "from": message.get("from"),
                        "timestamp": message.get("timestamp"),
                        "type": message.get("type"),
                        "text": (message.get("text") or {}).get("body")
                        if message.get("type") == "text"
                        else None,
                    }
                )
            for status in value.get("statuses", []) or []:
                found.append(
                    {
                        "wamid": status.get("id"),
                        "status": status.get("status"),
                        "timestamp": status.get("timestamp"),
                        "type": "status",
                    }
                )
    return found


def store_event(record: dict) -> Path:
    QUEUE.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = QUEUE / f"event-{stamp}-{uuid.uuid4().hex[:8]}.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.rename(path)
    return path


class Handler(BaseHTTPRequestHandler):
    server_version = "KTHWhatsAppWebhook/0.2-hosting"
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes, content_type="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send(200, b'{"status": "ok"}', "application/json")
            return
        if parsed.path == "/events":
            # Lectura de la cola para el consumidor autorizado (Albert).
            # La llave es el mismo token de verificación (secreto ya
            # distribuido solo entre Meta, Render y la bóveda local).
            params = parse_qs(parsed.query)
            key = self.headers.get("X-Events-Key") or (params.get("key") or [None])[0]
            expected = get_verify_token()
            if not expected or not key or not hmac.compare_digest(key, expected):
                self._send(403, b"forbidden")
                return
            since = (params.get("since") or [None])[0]
            records = []
            for path in sorted(QUEUE.glob("event-*.json"))[-100:]:
                try:
                    rec = json.loads(path.read_text(encoding="utf-8"))
                except (ValueError, OSError):
                    continue
                if since and rec.get("received_at", "") <= since:
                    continue
                rec["_file"] = path.name
                records.append(rec)
            body = json.dumps({"events": records}, ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json")
            return
        if parsed.path != "/webhook":
            self._send(404, b"not found")
            return
        # Verificación de Meta
        params = parse_qs(parsed.query)
        mode = (params.get("hub.mode") or [None])[0]
        token = (params.get("hub.verify_token") or [None])[0]
        challenge = (params.get("hub.challenge") or [""])[0]
        expected = get_verify_token()
        if mode == "subscribe" and expected and token and hmac.compare_digest(token, expected):
            log("GET /webhook verification OK")
            self._send(200, challenge.encode("utf-8"))
        else:
            log("GET /webhook verification REJECTED")
            self._send(403, b"forbidden")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/webhook":
            self._send(404, b"not found")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        signature = self.headers.get("X-Hub-Signature-256")
        verified = verify_signature(raw, signature)
        if verified is False:
            log("POST /webhook REJECTED: invalid signature")
            self._send(401, b"invalid signature")
            return
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
            payload_kind = "json"
        except (ValueError, UnicodeDecodeError):
            payload = raw.decode("utf-8", errors="replace")
            payload_kind = "raw"
        record = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "remote": self.client_address[0],
            "signature_header_present": signature is not None,
            "signature_verified": verified,  # null hasta que exista el app secret
            "payload_kind": payload_kind,
            "payload": payload,
            "messages_summary": extract_messages(payload),
        }
        path = store_event(record)
        log(f"POST /webhook stored {path.name} "
            f"(messages={len(record['messages_summary'])}, "
            f"signature_verified={verified})")
        # Respaldo en el log del servicio: si el disco efímero se reinicia,
        # el evento completo sigue recuperable desde los logs del hosting.
        log("EVENT_JSON " + json.dumps(record, ensure_ascii=False))
        self._send(200, b"EVENT_RECEIVED")

    def log_message(self, fmt, *args):  # silencio del logger por defecto
        pass


def main() -> int:
    if get_verify_token() is None:
        log("ERROR: falta el token de verificación "
            "(KTH_WA_VERIFY_TOKEN o secrets/verify_token.txt); no arranca.")
        return 1
    QUEUE.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    log(f"listening on http://{HOST}:{PORT} (webhook at /webhook, health at /health)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
