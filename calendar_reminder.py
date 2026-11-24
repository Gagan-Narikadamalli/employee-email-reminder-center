import base64
import json
import os
import re
import urllib.parse
import urllib.request
from flask import Blueprint, jsonify, request

calendar_reminder_bp = Blueprint("calendar_reminder", __name__)

SOURCES = {
    "sos": ("SOS_CALENDAR_API_URL", "SOS_CALENDAR_API_TOKEN", "SOS Call-Out Calendar"),
    "livingston": ("LIVINGSTON_CALENDAR_API_URL", "LIVINGSTON_CALENDAR_API_TOKEN", "SOS Livingston Call-Out Calendar"),
}

def normalize_phone(value):
    digits = re.sub(r"\\D", "", value or "")
    if len(digits) == 10:
        digits = "1" + digits
    return "+" + digits if 11 <= len(digits) <= 15 else ""

def fetch_calendar_contacts(source, kind):
    if source not in SOURCES or kind not in {"employee", "client"}:
        raise ValueError("Choose a valid calendar and recipient type.")
    url_key, token_key, label = SOURCES[source]
    base_url = os.environ.get(url_key, "").strip().rstrip("/")
    token = os.environ.get(token_key, "").strip()
    if not base_url or not token:
        raise RuntimeError(f"{label} connection is not configured.")
    url = base_url + "/api/reminder-contacts?" + urllib.parse.urlencode({"kind": kind})
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        data = json.loads(response.read().decode("utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("Calendar returned an unexpected contact response.")
    return data

@calendar_reminder_bp.get("/calendar-contacts")
def calendar_contacts():
    try:
        source = request.args.get("source", "sos")
        kind = request.args.get("kind", "employee")
        contacts = fetch_calendar_contacts(source, kind)
        return jsonify({"ok": True, "source": source, "kind": kind, "contacts": contacts})
    except urllib.error.HTTPError as exc:
        return jsonify({"ok": False, "error": "Calendar contact access failed (" + str(exc.code) + ")."}), 502
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502

def send_twilio_sms(to_phone, body):
    sid = os.environ["TWILIO_ACCOUNT_SID"]
    token = os.environ["TWILIO_AUTH_TOKEN"]
    sender = normalize_phone(os.environ["TWILIO_PHONE_NUMBER"])
    data = urllib.parse.urlencode({"To": to_phone, "From": sender, "Body": body}).encode()
    req = urllib.request.Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
        data=data,
        headers={"Authorization": "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode()},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode()).get("sid", "")

@calendar_reminder_bp.post("/calendar-contacts-send-sms")
def calendar_contacts_send_sms():
    if not all(os.environ.get(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_PHONE_NUMBER")):
        return jsonify({"ok": False, "error": "SMS is not configured."}), 503
    try:
        body = request.get_json(silent=True) or {}
        message = str(body.get("message") or "").strip()
        recipients = body.get("recipients") or []
        if not message:
            return jsonify({"ok": False, "error": "Enter a message before sending."}), 400
        if len(message) > 1000:
            return jsonify({"ok": False, "error": "Message must be 1,000 characters or fewer."}), 400
        if not isinstance(recipients, list) or not recipients or len(recipients) > 100:
            return jsonify({"ok": False, "error": "Select between 1 and 100 recipients."}), 400
        source, kind = body.get("source"), body.get("kind")
        if source not in SOURCES or kind not in {"employee", "client"}:
            return jsonify({"ok": False, "error": "Invalid calendar or recipient type."}), 400
        # Validate selected IDs against the upstream contact list to prevent arbitrary-number sends.
        contacts = fetch_calendar_contacts(source, kind)
        allowed = {str(c.get("id")): c for c in contacts}
        sent = skipped = failed = 0
        for recipient in recipients:
            record = allowed.get(str(recipient.get("id")))
            if not record:
                skipped += 1
                continue
            phone = normalize_phone(record.get("phone_number"))
            if not phone:
                skipped += 1
                continue
            try:
                send_twilio_sms(phone, message.replace("{first}", str(record.get("first_name") or "there")).replace("{name}", " ".join(filter(None, [record.get("first_name"), record.get("last_name")]))))
                sent += 1
            except Exception:
                failed += 1
        detail = f"SMS completed: {sent} sent, {skipped} skipped (missing or invalid phone/contact), {failed} failed."
        return jsonify({"ok": failed == 0, "message": detail, "sent": sent, "skipped": skipped, "failed": failed}), (200 if failed == 0 else 502)
    except urllib.error.HTTPError as exc:
        return jsonify({"ok": False, "error": "Calendar contact validation failed (" + str(exc.code) + ")."}), 502
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
