from __future__ import annotations

import csv
import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import urllib.parse
import urllib.request
import uuid
import webbrowser
import zipfile
from datetime import datetime
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import xml.etree.ElementTree as ET

from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)

# Only the SHA-256 digest is stored in this public repository. The password
# itself is never shipped to the browser or committed to source control.
ADMIN_PASSWORD_SHA256 = "17bd4b37413a0867e5d165476be2edd0e94b61b5eafb9217057e01a04a9a0f51"
MAINTENANCE_COOKIE = "sos_maintenance_access"


def maintenance_enabled() -> bool:
    return os.environ.get("MAINTENANCE_MODE", "true").strip().casefold() in {
        "1", "true", "yes", "on"
    }


def maintenance_access_token() -> str:
    return hmac.new(
        ADMIN_PASSWORD_SHA256.encode("utf-8"),
        b"employee-reminder-maintenance-access",
        hashlib.sha256,
    ).hexdigest()


def has_maintenance_access() -> bool:
    supplied = request.cookies.get(MAINTENANCE_COOKIE, "")
    return bool(supplied) and hmac.compare_digest(supplied, maintenance_access_token())


def maintenance_page(error: str = "") -> str:
    error_html = (
        f"<div class='maintenance-error'>{html.escape(error)}</div>" if error else ""
    )
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
    <meta name='viewport' content='width=device-width,initial-scale=1'>
    <title>Employee Reminder Center | Maintenance</title><style>
    :root{{--blue:#164b8f;--light:#f4f8fc;--ink:#17223b;--muted:#667085;}}
    *{{box-sizing:border-box}} body{{margin:0;min-height:100vh;display:grid;place-items:center;
    padding:24px;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--light);color:var(--ink)}}
    .panel{{width:min(620px,100%);background:#fff;border:1px solid #d9e2f0;border-radius:20px;padding:32px;
    box-shadow:0 14px 38px rgba(18,54,92,.12);text-align:center}}
    .mark{{width:68px;height:68px;margin:0 auto 18px;border-radius:20px;display:grid;place-items:center;
    color:#fff;font-size:27px;font-weight:900;background:linear-gradient(135deg,#1b75bb,#6346b8)}}
    h1{{margin:0 0 10px;font-size:30px}} p{{line-height:1.55;color:var(--muted)}}
    details{{margin-top:24px;text-align:left;border-top:1px solid #e4e7ec;padding-top:18px}}
    summary{{cursor:pointer;font-weight:750;color:var(--blue)}} label{{display:block;font-weight:700;margin:14px 0 6px}}
    input{{width:100%;padding:11px;border:1px solid #cbd5e1;border-radius:9px;font:inherit}}
    button{{margin-top:12px;width:100%;padding:11px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:800;cursor:pointer}}
    .maintenance-error{{margin-top:12px;padding:10px;border-radius:8px;background:#fef3f2;color:#b42318;font-weight:700}}
    </style></head><body><main class='panel'><div class='mark'>SOS</div>
    <h1>We’ll be back soon</h1><p>The Employee Reminder Center is currently under maintenance.
    Email and SMS reminder tools are temporarily unavailable while updates are completed.</p>
    <details><summary>Administrator access</summary>{error_html}
    <form method='post' action='/maintenance-access'><label for='maintenance-password'>Admin password</label>
    <input id='maintenance-password' name='password' type='password' autocomplete='current-password' required>
    <button type='submit'>Enter maintenance preview</button></form></details>
    </main></body></html>"""


@app.before_request
def require_admin_password():
    if request.endpoint == "maintenance_access":
        return None

    if maintenance_enabled():
        if has_maintenance_access():
            return None
        return Response(
            maintenance_page(),
            503,
            {"Cache-Control": "no-store, no-cache, must-revalidate, private"},
        )

    auth = request.authorization
    supplied_password = auth.password if auth else ""
    supplied_digest = hashlib.sha256(supplied_password.encode("utf-8")).hexdigest()

    if not hmac.compare_digest(supplied_digest, ADMIN_PASSWORD_SHA256):
        return Response(
            "Employee Reminder Center authentication required.",
            401,
            {
                "WWW-Authenticate": 'Basic realm="Employee Reminder Center", charset="UTF-8"',
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
            },
        )


@app.post("/maintenance-access")
def maintenance_access():
    if not maintenance_enabled():
        return redirect("/")

    supplied_password = request.form.get("password", "")
    supplied_digest = hashlib.sha256(supplied_password.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(supplied_digest, ADMIN_PASSWORD_SHA256):
        return Response(maintenance_page("Incorrect administrator password."), 401)

    response = redirect("/")
    response.set_cookie(
        MAINTENANCE_COOKIE,
        maintenance_access_token(),
        max_age=8 * 60 * 60,
        secure=request.is_secure or bool(os.environ.get("VERCEL")),
        httponly=True,
        samesite="Lax",
    )
    return response


@app.after_request
def prevent_protected_content_caching(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

HOST = "127.0.0.1"
PORT = 5051
ANALYSES: dict[str, dict] = {}

CSS = """
:root { --ink:#17223b; --muted:#667085; --line:#d9e2f0; --bg:#f4f8fc; --card:#ffffff; --ok:#087f5b; --warn:#b54708; --bad:#b42318; --primary:#164b8f; --primary-dark:#103865; --sos-blue:#1b75bb; --sos-yellow:#f4c542; --sos-red:#e54b4b; --sos-green:#36a269; --gmail:#c5221f; }
* { box-sizing:border-box; }
body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--ink); }
main { max-width:1120px; margin:0 auto; padding:26px 18px 60px; }
h1 { margin:0; font-size:30px; } h2 { margin:0 0 10px; font-size:20px; }
p { line-height:1.5; }
.topline { display:flex; justify-content:space-between; gap:16px; align-items:center; flex-wrap:wrap; margin-bottom:18px; }
.brand { display:flex; align-items:center; gap:14px; }
.brand-mark { width:58px; height:58px; border-radius:18px; display:grid; place-items:center; color:#fff; font-size:25px; font-weight:900; background:linear-gradient(135deg,var(--sos-blue),#6346b8); box-shadow:0 8px 20px rgba(22,75,143,.22); }
.badge-email { display:inline-block; background:#eaf4ff; color:var(--primary); border:1px solid #b9d8f5; border-radius:999px; padding:5px 10px; font-size:12px; font-weight:800; letter-spacing:.02em; }
.card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:19px; margin:14px 0; box-shadow:0 5px 18px rgba(18,54,92,.055); }
.muted { color:var(--muted); } .small { font-size:13px; }
.status-ok { color:var(--ok); font-weight:750; } .status-warn { color:var(--warn); font-weight:750; } .status-bad { color:var(--bad); font-weight:750; }
.upload { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
.connect-row { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
.workbook-slots { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px; }
.workbook-slot { display:flex; gap:9px; align-items:flex-start; border:1px solid var(--line); border-radius:10px; padding:10px; background:#f9fafb; }
.workbook-slot input { margin-top:3px; flex:0 0 auto; }
.workbook-slot-name { display:block; font-weight:750; color:#344054; overflow-wrap:anywhere; }
.employee-head { display:flex; justify-content:space-between; gap:16px; align-items:flex-start; flex-wrap:wrap; }
label { display:block; font-weight:700; margin-bottom:6px; }
input[type=file], input[type=text], textarea { width:100%; border:1px solid #d0d5dd; border-radius:9px; padding:10px; background:#fff; font:inherit; }
input[type=checkbox] { width:17px; height:17px; margin:0; }
button, .button { border:0; border-radius:9px; padding:10px 15px; font-weight:750; cursor:pointer; font-size:14px; text-decoration:none; display:inline-block; }
button:disabled { cursor:not-allowed; opacity:.6; }
.primary { background:var(--primary); color:#fff; } .primary:hover { background:var(--primary-dark); } .gmail { background:var(--gmail); color:#fff; } .secondary { background:#eaf0f7; color:#344054; }
.sms { background:#067647; color:#fff; }
.sms-panel { border-left:4px solid #12b76a; background:#f0fdf4; padding:12px 14px; border-radius:8px; margin:12px 0; }
.actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; align-items:center; }
.metrics { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; margin:18px 0; }
.metric { background:#fff; border:1px solid var(--line); border-top:4px solid var(--sos-blue); border-radius:12px; padding:14px; }
.metric strong { display:block; font-size:25px; margin-top:3px; }
.success { border-left:4px solid #12b76a; background:#ecfdf3; padding:12px 14px; border-radius:8px; margin:12px 0; }
.error, .notice { border-left:4px solid #f04438; background:#fef3f2; padding:12px 14px; border-radius:8px; margin:12px 0; }
.info { border-left:4px solid #6172f3; background:#eef4ff; padding:12px 14px; border-radius:8px; margin:12px 0; }
table { width:100%; border-collapse:collapse; margin-top:12px; font-size:14px; }
th,td { border-bottom:1px solid var(--line); padding:9px 8px; text-align:left; } th { color:#475467; background:#f9fafb; }
.email-box { border:1px solid var(--line); border-radius:11px; padding:12px; background:#fafafa; margin-top:12px; }
.inline-form { display:inline; }
summary { cursor:pointer; font-weight:700; color:#475467; }
.selection-bar { position:sticky; top:10px; z-index:5; display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; background:#fff; border:2px solid #b9d8f5; border-radius:15px; padding:13px 15px; margin:16px 0; box-shadow:0 9px 24px rgba(22,75,143,.14); }
.recipient-select { display:flex; align-items:flex-start; gap:10px; }
.recipient-select input { margin-top:4px; flex:0 0 auto; }
.selected-card { border-color:var(--sos-blue); box-shadow:0 7px 22px rgba(27,117,187,.14); }
.channel-actions { display:flex; gap:8px; flex-wrap:wrap; }
@media (max-width:760px) { .upload,.metrics,.workbook-slots { grid-template-columns:1fr; } }
"""


def esc(v) -> str:
    return html.escape(str(v or ""), quote=True)


def normalize_email(value: str | None) -> str:
    return (value or "").strip().casefold()


def normalize_name(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").casefold())


def normalize_phone(value: str | None) -> str:
    digits = re.sub(r"\D", "", value or "")
    if len(digits) == 10:
        digits = "1" + digits
    return "+" + digits if 11 <= len(digits) <= 15 else ""


def truthy(v: str | None) -> bool:
    return (v or "").strip().casefold() in {"1", "true", "yes", "y"}


def zeroish(v: str | None) -> bool:
    return (v or "").strip().casefold() in {"", "0", "false", "no", "n"}


def read_missing_csv(file_bytes: bytes) -> tuple[list[dict], dict]:
    text = file_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    required = {"Principal1Name", "Principal2Name", "StartDateTime"}
    if not required.issubset(set(reader.fieldnames or [])):
        raise ValueError("CSV is missing required columns: Principal1Name, Principal2Name, StartDateTime")
    filtered = []
    excluded_converted = 0
    excluded_other = 0
    for row in rows:
        if "IsConvertable" in row and not truthy(row.get("IsConvertable")):
            excluded_other += 1
            continue
        if "ConvertedToTimesheet" in row and not zeroish(row.get("ConvertedToTimesheet")):
            excluded_converted += 1
            continue
        if "Cancelled" in row and not zeroish(row.get("Cancelled")):
            excluded_other += 1
            continue
        if "Deleted" in row and not zeroish(row.get("Deleted")):
            excluded_other += 1
            continue
        filtered.append(row)
    return filtered, {
        "raw_count": len(rows),
        "included_count": len(filtered),
        "excluded_converted": excluded_converted,
        "excluded_other": excluded_other,
    }


def column_number(cell_ref: str) -> int:
    letters = re.match(r"[A-Z]+", cell_ref.upper())
    if not letters:
        return 0
    n = 0
    for ch in letters.group(0):
        n = n * 26 + ord(ch) - 64
    return n - 1


def read_employee_contacts_xlsx(file_bytes: bytes, target_sheet: str = "Employee Contact Info") -> list[dict]:
    ns_main = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    ns_rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    ns_pkg_rel = "http://schemas.openxmlformats.org/package/2006/relationships"
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall(f"{{{ns_main}}}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{{{ns_main}}}t")))

        workbook = ET.fromstring(z.read("xl/workbook.xml"))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rel_map = {r.attrib["Id"]: r.attrib["Target"] for r in rels.findall(f"{{{ns_pkg_rel}}}Relationship")}
        sheet_path = None
        sheets_node = workbook.find(f"{{{ns_main}}}sheets")
        for s in list(sheets_node or []):
            if s.attrib.get("name") == target_sheet:
                rid = s.attrib.get(f"{{{ns_rel}}}id")
                target = rel_map.get(rid, "")
                if target.startswith("/"):
                    sheet_path = target.lstrip("/")
                elif target.startswith("xl/"):
                    sheet_path = target
                else:
                    sheet_path = "xl/" + target.lstrip("/")
                break
        if not sheet_path or sheet_path not in z.namelist():
            raise ValueError(f"Excel workbook does not contain a '{target_sheet}' sheet")

        root = ET.fromstring(z.read(sheet_path))
        parsed_rows = []
        for row in root.iter(f"{{{ns_main}}}row"):
            values = {}
            for c in row.findall(f"{{{ns_main}}}c"):
                col = column_number(c.attrib.get("r", "A1"))
                typ = c.attrib.get("t")
                value = ""
                if typ == "inlineStr":
                    is_node = c.find(f"{{{ns_main}}}is")
                    if is_node is not None:
                        value = "".join(t.text or "" for t in is_node.iter(f"{{{ns_main}}}t"))
                else:
                    v = c.find(f"{{{ns_main}}}v")
                    raw = v.text if v is not None and v.text is not None else ""
                    if typ == "s" and raw:
                        try:
                            value = shared[int(raw)]
                        except (ValueError, IndexError):
                            value = raw
                    else:
                        value = raw
                values[col] = value
            if values:
                parsed_rows.append([values.get(i, "") for i in range(max(values) + 1)])

    header_idx, header = None, []
    phone_aliases = {"phone", "phone number", "mobile", "mobile number", "cell", "cell phone", "cellphone"}
    for i, row in enumerate(parsed_rows):
        cleaned = [str(x).strip() for x in row]
        lowered = {x.casefold() for x in cleaned}
        if {"employee", "email"}.issubset(lowered):
            header_idx, header = i, cleaned
            break
    if header_idx is None:
        raise ValueError("Could not find Employee / Email headers in Employee Contact Info sheet")
    col_map = {name.casefold(): idx for idx, name in enumerate(header) if name}
    phone_column = next((name for name in phone_aliases if name in col_map), None)
    contacts = []
    for row in parsed_rows[header_idx + 1:]:
        def get(name: str) -> str:
            idx = col_map[name.casefold()]
            return str(row[idx]).strip() if idx < len(row) else ""
        employee = get("Employee")
        if employee:
            phone = ""
            if phone_column:
                idx = col_map[phone_column]
                phone = str(row[idx]).strip() if idx < len(row) else ""
            contacts.append({"Employee": employee, "Email": get("Email"), "Phone": phone})
    return contacts


def format_appointment(row: dict) -> dict:
    start = (row.get("StartDateTime") or "").strip()
    end = (row.get("EndDateTime") or "").strip()
    try:
        start_dt = datetime.strptime(start, "%m/%d/%Y %H:%M")
        end_dt = datetime.strptime(end, "%m/%d/%Y %H:%M") if end else None
        date_text = start_dt.strftime("%b %d, %Y")
        time_text = start_dt.strftime("%I:%M %p").lstrip("0")
        if end_dt:
            time_text += " – " + end_dt.strftime("%I:%M %p").lstrip("0")
    except Exception:
        date_text, time_text = start, end
    return {"date": date_text, "time": time_text, "client": (row.get("Principal2Name") or "").strip()}


def usable_csv_email(value: str | None) -> str:
    email = normalize_email(value)
    if not email or email in {"withheld", "none", "n/a", "na", "unknown"} or "@" not in email:
        return ""
    return email


def _safe_unique_contact(candidates: list[dict]) -> dict | None:
    """Return a contact only when duplicate rows contain the same contact details."""
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    identities = {
        (
            normalize_name(c.get("Employee")),
            normalize_email(c.get("Email")),
            normalize_phone(c.get("Phone")),
        )
        for c in candidates
    }
    if len(identities) == 1:
        return candidates[0]
    return None


def analyze_files(csv_bytes: bytes, xlsx_bytes: bytes) -> dict:
    missing, filter_stats = read_missing_csv(csv_bytes)
    contacts = read_employee_contacts_xlsx(xlsx_bytes)

    # Principal1Name is the only matching key. Email addresses and phone numbers
    # are always taken from the matched Employee Contact Info row in the workbook.
    contacts_by_name: dict[str, list[dict]] = {}
    for contact in contacts:
        name_key = normalize_name(contact.get("Employee"))
        if name_key:
            contacts_by_name.setdefault(name_key, []).append(contact)

    grouped: dict[str, dict] = {}
    for row in missing:
        raw_name = (row.get("Principal1Name") or "Unknown employee").strip()
        raw_email = (row.get("Principal1Email") or "").strip()
        principal_id = (row.get("Principal1") or "").strip()
        name_key = normalize_name(raw_name)

        key = name_key or (f"principal1:{principal_id}" if principal_id else "unknown-employee")
        group = grouped.setdefault(
            key,
            {
                "key": key,
                "rows": [],
                "csv_names": [],
                "csv_emails": [],
                "principal_ids": [],
            },
        )
        group["rows"].append(row)
        if raw_name:
            group["csv_names"].append(raw_name)
        if raw_email:
            group["csv_emails"].append(raw_email)
        if principal_id:
            group["principal_ids"].append(principal_id)

    employees = []
    for key, group in grouped.items():
        # Preserve first-seen order while removing duplicates.
        csv_names = list(dict.fromkeys(n for n in group["csv_names"] if n))
        csv_emails = list(dict.fromkeys(e for e in group["csv_emails"] if e))
        principal_ids = list(dict.fromkeys(group["principal_ids"]))

        contact = None
        match_method = "none"
        match_note = ""

        # Match CSV Principal1Name to Excel Employee. The Excel sheet is the sole
        # source for the final email address and phone number.
        normalized_names = list(dict.fromkeys(normalize_name(n) for n in csv_names if normalize_name(n)))
        if len(normalized_names) == 1:
            candidates = contacts_by_name.get(normalized_names[0], [])
            contact = _safe_unique_contact(candidates)
            if contact:
                match_method = "name"
                match_note = "Matched CSV Principal1Name to Excel Employee. Email and phone come from Employee Contact Info."
            elif candidates:
                match_note = "Employee name appears multiple times with conflicting contact details in Employee Contact Info."
            else:
                match_note = "CSV Principal1Name was not found in the Excel Employee column."
        elif len(normalized_names) > 1:
            match_note = "CSV contains multiple different employee names for the same group; review before sending."
        else:
            match_note = "CSV Principal1Name is blank or invalid; review before sending."

        # Employee Contact Info is authoritative for the final recipient identity.
        # If no safe contact exists, show the most common CSV name only for review.
        if contact:
            display_name = (contact.get("Employee") or "Unknown employee").strip()
        else:
            name_counts = {}
            for n in csv_names:
                name_counts[n] = name_counts.get(n, 0) + sum(1 for r in group["rows"] if (r.get("Principal1Name") or "").strip() == n)
            display_name = max(name_counts, key=name_counts.get) if name_counts else "Unknown employee"

        contact_email = (contact.get("Email") or "").strip() if contact else ""
        contact_phone = normalize_phone(contact.get("Phone")) if contact else ""
        appointments = [format_appointment(r) for r in sorted(group["rows"], key=lambda r: r.get("StartDateTime", ""))]
        count = len(group["rows"])
        first = display_name.split()[0] if display_name else "there"
        appointment_word = "appointment" if count == 1 else "appointments"
        verb = "needs" if count == 1 else "need"
        conversion_word = "conversion" if count == 1 else "conversions"
        message = (
            f"Hi {first}, this is a reminder that you currently have {count} {appointment_word} "
            f"that still {verb} to be converted. Please check the scheduling/timesheet system "
            f"and complete the missing {conversion_word}. Thank you."
        )
        subject = f"Reminder: {count} missing appointment conversion{'s' if count != 1 else ''}"
        email_url = gmail_compose_url(contact_email, subject, message) if contact_email else None

        contact_name_norm = normalize_name(display_name) if contact else ""
        csv_name_norms = {normalize_name(n) for n in csv_names if normalize_name(n)}
        name_mismatch = bool(contact and csv_name_norms and (csv_name_norms != {contact_name_norm}))
        generic_account = False
        review_needed = not bool(contact)

        employees.append({
            "key": key,
            "name": display_name,
            "csv_email": ", ".join(csv_emails),
            "csv_names": csv_names,
            "principal_ids": principal_ids,
            "contact_email": contact_email,
            "contact_phone": contact_phone,
            "contact_found": bool(contact),
            "match_method": match_method,
            "match_note": match_note,
            "name_mismatch": name_mismatch,
            "generic_account": generic_account,
            "review_needed": review_needed,
            "count": count,
            "appointments": appointments,
            "message": message,
            "subject": subject,
            "email_url": email_url,
        })

    employees.sort(key=lambda e: (-e["count"], e["name"].casefold()))
    return {
        "analysis_id": str(uuid.uuid4()),
        "filter_stats": filter_stats,
        "total_missing": len(missing),
        "employee_count": len(employees),
        "contact_count": sum(bool(e["contact_found"]) for e in employees),
        "review_count": sum(bool(e["review_needed"]) for e in employees),
        "employees": employees,
    }


def gmail_compose_url(to_email: str, subject: str, body: str) -> str:
    params = {"view": "cm", "fs": "1", "to": to_email, "su": subject, "body": body}
    return "https://mail.google.com/mail/?" + urllib.parse.urlencode(
        params, quote_via=urllib.parse.quote
    )


def sms_configured() -> bool:
    return all(os.environ.get(k) for k in (
        "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_PHONE_NUMBER"
    ))


def signed_payload(data: dict) -> tuple[str, str]:
    payload = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    signature = hmac.new(os.environ.get("TWILIO_AUTH_TOKEN", "not-configured").encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload, signature


def read_signed_payload(payload: str, signature: str) -> dict:
    expected = hmac.new(os.environ["TWILIO_AUTH_TOKEN"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature or ""):
        raise ValueError("The reminder data could not be verified. Analyze the files again.")
    return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())


def send_twilio_sms(to_phone: str, body: str) -> str:
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
        result = json.loads(response.read().decode())
    return str(result.get("sid", ""))


def page(result: dict | None = None, error: str | None = None, notice: str | None = None) -> str:
    parts = [f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Employee Reminder Center | SOS</title><style>{CSS}</style></head><body><main>
    <div class='topline'><div class='brand'><div class='brand-mark' aria-hidden='true'>SOS</div><div><span class='badge-email'>SUCCESS ON THE SPECTRUM</span><h1 style='margin-top:8px'>Employee Reminder Center</h1>
    <p class='muted' style='margin:7px 0 0'>Review outstanding documentation and send personalized email or SMS reminders.</p></div></div></div>
    <div class='info'><strong>Contacts come directly from the uploaded Excel workbook.</strong> Email opens a prepared Gmail draft. SMS sends through Twilio after confirmation. The existing employee matching and recipient workflow remains unchanged.</div>
    <div class='card'><h2>Analyze employee reminders</h2><form id='analyzeForm' method='post' action='/analyze' enctype='multipart/form-data'><div class='upload'>
      <div><label>Unfiltered appointments CSV</label><input type='file' name='csv_file' accept='.csv' required><div class='muted small' style='margin-top:6px'>Converted, cancelled, deleted, and non-convertible rows are removed automatically.</div></div>
      <div><label>Employee contacts Excel</label><input id='xlsxFile' type='file' name='xlsx_file' accept='.xlsx'>
      <div id='savedWorkbookStatus' class='muted small' style='margin-top:6px'>Checking for saved employee workbooks...</div>
      <div id='savedWorkbookSlots' class='workbook-slots' aria-label='Saved employee workbooks'></div></div>
    </div>
    <div class='connect-row' style='margin-top:12px'><input id='saveWorkbook' type='checkbox'><label for='saveWorkbook' style='margin:0'>Save this employee workbook in this browser</label></div>
    <div id='saveTargetPanel' hidden style='margin-top:10px'><strong>Choose which saved Excel workbook to replace</strong><div id='saveTargetSlots' class='workbook-slots'></div></div>
    <div class='muted small' style='margin-top:5px'>Saving is off until selected. When saving, choose Slot 1 or Slot 2 so the other location’s workbook stays unchanged.</div>
    <div class='actions'><button class='primary' type='submit'>Analyze Files</button><button id='clearSavedWorkbook' class='secondary' type='button'>Remove both saved workbooks</button></div>
    <div id='analyzeStatus' class='muted small' style='margin-top:8px'></div></form></div>"""]

    if error:
        parts.append(f"<div class='error'><strong>Could not analyze files:</strong> {esc(error)}</div>")
    if notice:
        parts.append(f"<div class='success'><strong>{esc(notice)}</strong></div>")

    if result:
        eligible = [e for e in result['employees'] if e.get('contact_email') and e.get('contact_found')]
        sms_candidates = [e for e in result['employees'] if e.get('contact_phone') and e.get('contact_found')]
        bulk_data = [{"key": e["key"], "name": e["name"], "phone": e["contact_phone"], "message": e["message"]} for e in sms_candidates]
        bulk_payload, bulk_signature = signed_payload({"recipients": bulk_data})
        if eligible:
            bulk_action = f"<button id='sendSelectedEmail' class='gmail' type='button' onclick='openSelectedGmailDrafts()'>Email selected (0)</button>"
        else:
            bulk_action = "<button class='secondary' type='button' disabled>Open All in Gmail</button>"
        parts.append(f"""
        <div class='metrics'>
          <div class='metric'><span class='muted'>Unconverted appointments</span><strong>{result['total_missing']}</strong><span class='muted small'>{result['filter_stats']['excluded_converted']} already converted row{'s' if result['filter_stats']['excluded_converted'] != 1 else ''} excluded</span></div>
          <div class='metric'><span class='muted'>Employees</span><strong>{result['employee_count']}</strong></div>
          <div class='metric'><span class='muted'>Ready to email / SMS</span><strong>{len(eligible)} / {len(sms_candidates)}</strong></div>
        </div>
        <div class='selection-bar'>
          <div><strong><span id='selectedCount'>0</span> people selected</strong><div class='muted small'>Choose everyone or only the employees you want to contact.</div></div>
          <div class='channel-actions'><button class='secondary' type='button' onclick='selectAllRecipients()'>Select all</button><button class='secondary' type='button' onclick='clearAllRecipients()'>Clear all</button>{bulk_action}</div>
        </div>
        <div class='card'>
          <div class='employee-head'><div><h2>Text eligible employees</h2>
          <div class='muted'>{len(sms_candidates)} matched employee{'s' if len(sms_candidates) != 1 else ''} have a valid phone number from the uploaded workbook.</div>
          <div class='muted small'>No message is sent until you confirm. Rows without a valid phone number are skipped.</div></div></div>
          <form id='bulkSmsForm' class='sms-send-form' method='post' action='/send-sms' data-bulk='true' data-confirm='Send an SMS to the selected employees who have a valid phone number?'>
            <input type='hidden' name='payload' value='{esc(bulk_payload)}'><input type='hidden' name='signature' value='{esc(bulk_signature)}'>
            <input id='selectedRecipientKeys' type='hidden' name='selected_keys' value=''>
            <div class='connect-row' style='margin-top:14px'><input id='automaticMessage' type='radio' name='message_mode' value='automatic' checked><label for='automaticMessage' style='margin:0'>Automated missing-documentation reminder</label></div>
            <div class='connect-row' style='margin-top:8px'><input id='customMessageMode' type='radio' name='message_mode' value='custom'><label for='customMessageMode' style='margin:0'>Custom one-time message</label></div>
            <div id='customMessageFields' style='margin-top:12px'><label for='customMessage'>Custom message</label><textarea id='customMessage' name='custom_message' rows='4' maxlength='1000' placeholder='Example: Today is a holiday. The center will reopen tomorrow.'></textarea><div class='muted small'>This text is sent only when “Custom one-time message” is selected. <span id='customCount'>0</span>/1000 characters.</div></div>
            <div class='actions'><button id='sendSelectedSms' class='sms' type='submit' data-configured='{'true' if sms_configured() else 'false'}' {'disabled' if not sms_candidates or not sms_configured() else ''}>SMS selected (0)</button></div><div class='sms-result small' aria-live='polite'></div>
          </form>
        </div>
        <h2 style='margin-top:26px'>Individual reminders</h2>
        """)

        for emp in result['employees']:
            safe = bool(emp.get('contact_email') and emp.get('contact_found'))
            status = "<span class='status-ok'>Ready</span>" if safe else "<span class='status-warn'>Review needed</span>"
            rows = "".join(f"<tr><td>{esc(a['date'])}</td><td>{esc(a['time'])}</td></tr>" for a in emp['appointments'])

            if safe:
                action = f"<a class='button gmail gmail-draft-link' target='_blank' rel='noopener' href='{esc(emp['email_url'])}'>Open in Gmail</a>"
            else:
                action = "<button class='secondary' type='button' disabled>Open in Gmail</button><div class='muted small' style='margin-top:6px'>This employee does not have a safe matched email yet.</div>"

            one_payload, one_signature = signed_payload({"recipients": [{"name": emp["name"], "phone": emp.get("contact_phone", ""), "message": emp["message"]}]})
            sms_action = "<button class='secondary' type='button' disabled>Send SMS</button>"
            if emp.get("contact_phone") and emp.get("contact_found") and sms_configured():
                sms_action = f"""<form class='sms-send-form' method='post' action='/send-sms' data-confirm='Send this SMS reminder now?'>
                <input type='hidden' name='payload' value='{esc(one_payload)}'><input type='hidden' name='signature' value='{esc(one_signature)}'>
                <button class='sms' type='submit'>Send SMS</button><div class='sms-result small' aria-live='polite'></div></form>"""

            parts.append(f"""
            <section class='card recipient-card' data-recipient-key='{esc(emp['key'])}'>
              <div class='employee-head'>
                <div class='recipient-select'><input class='recipient-checkbox' type='checkbox' value='{esc(emp['key'])}' data-email-url='{esc(emp['email_url'] or '')}' data-has-phone='{'true' if emp.get('contact_phone') and emp.get('contact_found') else 'false'}' aria-label='Select {esc(emp['name'])}'><div><div style='font-size:19px;font-weight:800'>{esc(emp['name'])}</div><div class='muted'>{esc(emp['contact_email']) or 'No matched email'}</div><div class='muted small'>{esc(emp['match_note'])}</div></div></div>
                <div style='text-align:right'><strong>{emp['count']}</strong> missing appointment{'s' if emp['count'] != 1 else ''}<br>{status}</div>
              </div>
              <table><thead><tr><th>Date</th><th>Time</th></tr></thead><tbody>{rows}</tbody></table>
              <div class='email-box'><div><strong>Subject:</strong> {esc(emp['subject'])}</div>
                <textarea rows='3' readonly style='margin-top:9px'>{esc(emp['message'])}</textarea>
                <div class='employee-head' style='margin-top:10px'><div class='muted small'>Gmail uses the account currently active/default in this browser.</div><div>{action}</div></div>
              </div>
              <div class='sms-panel'><strong>SMS</strong><div class='muted small'>Phone: {esc(emp.get('contact_phone')) or 'No valid phone found'}</div>
              <div class='actions'>{sms_action}</div></div>
            </section>
            """)

        parts.append("""
        <script>
        function selectedRecipientBoxes() { return Array.from(document.querySelectorAll('.recipient-checkbox:checked')); }
        function updateRecipientSelection() {
          const selected = selectedRecipientBoxes();
          document.getElementById('selectedCount').textContent = selected.length;
          document.querySelectorAll('.recipient-card').forEach(card => card.classList.toggle('selected-card', card.querySelector('.recipient-checkbox').checked));
          const emailCount = selected.filter(box => box.dataset.emailUrl).length;
          const smsCount = selected.filter(box => box.dataset.hasPhone === 'true').length;
          const emailButton = document.getElementById('sendSelectedEmail');
          if (emailButton) { emailButton.textContent = `Email selected (${emailCount})`; emailButton.disabled = emailCount === 0; }
          const smsButton = document.getElementById('sendSelectedSms');
          if (smsButton) { smsButton.textContent = `SMS selected (${smsCount})`; smsButton.disabled = smsCount === 0 || smsButton.dataset.configured === 'false'; }
          const selectedKeys = document.getElementById('selectedRecipientKeys');
          if (selectedKeys) selectedKeys.value = selected.map(box => box.value).join(',');
        }
        function selectAllRecipients() { document.querySelectorAll('.recipient-checkbox').forEach(box => box.checked = true); updateRecipientSelection(); }
        function clearAllRecipients() { document.querySelectorAll('.recipient-checkbox').forEach(box => box.checked = false); updateRecipientSelection(); }
        function openSelectedGmailDrafts() {
          const boxes = selectedRecipientBoxes().filter(box => box.dataset.emailUrl);
          if (!boxes.length) { alert('Select at least one employee with a valid email address.'); return; }
          if (!confirm(`Open ${boxes.length} personalized Gmail compose tab${boxes.length === 1 ? '' : 's'}? You will still click Send in Gmail for each message.`)) return;
          let blocked = 0;
          for (const box of boxes) {
            const w = window.open(box.dataset.emailUrl, '_blank');
            if (!w) blocked += 1;
          }
          if (blocked) alert('Your browser blocked one or more Gmail tabs. Allow pop-ups, then try again.');
        }
        document.querySelectorAll('.recipient-checkbox').forEach(box => box.addEventListener('change', updateRecipientSelection));
        updateRecipientSelection();
        </script>
        """)

    parts.append("""
    <script>
    const workbookDbName = 'employee-reminder-center';
    const workbookStore = 'saved-files';
    const workbookStatusCacheKey = 'employee-reminder-saved-workbooks';
    let workbookDbPromise = null;
    function openWorkbookDb() {
      if (workbookDbPromise) return workbookDbPromise;
      workbookDbPromise = new Promise((resolve, reject) => {
        const req = indexedDB.open(workbookDbName, 1);
        req.onupgradeneeded = () => req.result.createObjectStore(workbookStore, {keyPath:'id'});
        req.onsuccess = () => {
          const db = req.result;
          db.onversionchange = () => { db.close(); workbookDbPromise = null; };
          resolve(db);
        };
        req.onerror = () => { workbookDbPromise = null; reject(req.error); };
        req.onblocked = () => { workbookDbPromise = null; reject(new Error('Saved workbook storage is temporarily busy.')); };
      });
      return workbookDbPromise;
    }
    async function getWorkbook(id) {
      const db = await openWorkbookDb();
      return new Promise((resolve, reject) => {
        const req = db.transaction(workbookStore).objectStore(workbookStore).get(id);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => reject(req.error);
      });
    }
    async function savedWorkbooks() {
      const db = await openWorkbookDb();
      const [slot1, slot2, legacy] = await new Promise((resolve, reject) => {
        const tx = db.transaction(workbookStore);
        const store = tx.objectStore(workbookStore);
        const requests = [
          store.get('employee-contacts-1'),
          store.get('employee-contacts-2'),
          store.get('employee-contacts')
        ];
        tx.oncomplete = () => resolve(requests.map(req => req.result || null));
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error || new Error('Could not read saved workbooks.'));
      });
      if (!slot1 && legacy) {
        const db = await openWorkbookDb();
        await new Promise((resolve, reject) => {
          const tx = db.transaction(workbookStore, 'readwrite');
          tx.objectStore(workbookStore).put({...legacy, id:'employee-contacts-1'});
          tx.objectStore(workbookStore).delete('employee-contacts');
          tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
        });
        return [await getWorkbook('employee-contacts-1'), slot2];
      }
      return [slot1, slot2];
    }
    async function storeWorkbook(file, slot) {
      const db = await openWorkbookDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(workbookStore, 'readwrite');
        tx.objectStore(workbookStore).put({id:`employee-contacts-${slot}`, name:file.name, type:file.type, blob:file, savedAt:Date.now()});
        tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
      });
    }
    async function removeWorkbooks() {
      const db = await openWorkbookDb();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(workbookStore, 'readwrite');
        const store = tx.objectStore(workbookStore);
        store.delete('employee-contacts');
        store.delete('employee-contacts-1');
        store.delete('employee-contacts-2');
        tx.oncomplete = resolve; tx.onerror = () => reject(tx.error);
      });
    }
    function renderWorkbookStatus(saved) {
      const node = document.getElementById('savedWorkbookStatus');
      const slotsNode = document.getElementById('savedWorkbookSlots');
      const saveTargetSlots = document.getElementById('saveTargetSlots');
      if (!node) return;
      const count = saved.filter(Boolean).length;
      node.textContent = count ? `${count} saved workbook${count === 1 ? '' : 's'} available. Choose a slot or upload a new Excel file.` : 'No workbook is saved. Upload one, then select “Save” if you want to keep it.';
      if (slotsNode) slotsNode.innerHTML = saved.map((item, index) => {
        const slot = index + 1;
        const name = item ? item.name : 'Empty';
        return `<label class="workbook-slot"><input type="radio" name="saved_workbook_slot" value="${slot}"${item ? '' : ' disabled'}><span><strong>Analyze with Saved Excel ${slot}</strong><span class="workbook-slot-name">${escapeHtml(name)}</span></span></label>`;
      }).join('');
      if (saveTargetSlots) saveTargetSlots.innerHTML = saved.map((item, index) => {
        const slot = index + 1;
        const name = item ? item.name : 'Empty slot';
        return `<label class="workbook-slot"><input type="radio" name="save_workbook_slot" value="${slot}"><span><strong>Replace Saved Excel ${slot}</strong><span class="workbook-slot-name">${escapeHtml(name)}</span></span></label>`;
      }).join('');
    }
    async function refreshWorkbookStatus() {
      const node = document.getElementById('savedWorkbookStatus');
      if (!node) return;
      try {
        const saved = await savedWorkbooks();
        renderWorkbookStatus(saved);
        sessionStorage.setItem(workbookStatusCacheKey, JSON.stringify(saved.map(item => item ? {name:item.name} : null)));
      } catch (_) {
        if (!document.querySelector('input[name="saved_workbook_slot"]')) node.textContent = 'This browser could not access saved file storage.';
      }
    }
    function escapeHtml(value) {
      const node = document.createElement('div');
      node.textContent = value || '';
      return node.innerHTML;
    }
    const analyzeForm = document.getElementById('analyzeForm');
    const saveWorkbookCheckbox = document.getElementById('saveWorkbook');
    if (saveWorkbookCheckbox) saveWorkbookCheckbox.addEventListener('change', () => {
      document.getElementById('saveTargetPanel').hidden = !saveWorkbookCheckbox.checked;
      if (!saveWorkbookCheckbox.checked) document.querySelectorAll('input[name="save_workbook_slot"]').forEach(input => input.checked = false);
    });
    if (analyzeForm) analyzeForm.addEventListener('submit', async event => {
      event.preventDefault();
      const status = document.getElementById('analyzeStatus');
      const selected = document.getElementById('xlsxFile').files[0];
      let workbook = selected;
      try {
        if (saveWorkbookCheckbox.checked) {
          if (!selected) throw new Error('Choose a new employee Excel workbook before selecting Save. To use an existing workbook, leave Save unchecked and choose an Analyze slot.');
          const target = document.querySelector('input[name="save_workbook_slot"]:checked');
          if (!target) throw new Error('Choose Saved Excel 1 or Saved Excel 2 to replace.');
          const current = await getWorkbook(`employee-contacts-${target.value}`);
          if (current && !confirm(`Replace “${current.name}” in Saved Excel ${target.value} with “${selected.name}”?`)) return;
          await storeWorkbook(selected, target.value);
          await refreshWorkbookStatus();
        }
        if (!workbook) {
          const slot = document.querySelector('input[name="saved_workbook_slot"]:checked');
          const saved = slot ? await getWorkbook(`employee-contacts-${slot.value}`) : null;
          if (saved) workbook = new File([saved.blob], saved.name, {type:saved.type || 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
        }
        if (!workbook) throw new Error('Choose Saved Excel 1 or Saved Excel 2 to analyze, or upload a new employee Excel workbook.');
        status.textContent = 'Analyzing files...';
        const data = new FormData(analyzeForm);
        data.set('xlsx_file', workbook, workbook.name);
        const response = await fetch('/analyze', {method:'POST', body:data});
        const body = await response.text();
        document.open(); document.write(body); document.close();
      } catch (error) { status.textContent = error.message; status.className = 'status-bad small'; }
    });
    const clearButton = document.getElementById('clearSavedWorkbook');
    if (clearButton) clearButton.addEventListener('click', async () => {
      if (!confirm('Remove both saved employee workbooks from this browser?')) return;
      await removeWorkbooks(); await refreshWorkbookStatus();
    });
    document.querySelectorAll('.sms-send-form').forEach(form => form.addEventListener('submit', async event => {
      event.preventDefault();
      if (form.dataset.bulk === 'true' && !document.getElementById('selectedRecipientKeys').value) {
        const result = form.querySelector('.sms-result');
        result.textContent = 'Select at least one employee before sending.';
        result.className = 'sms-result status-bad small';
        return;
      }
      if (!confirm(form.dataset.confirm || 'Send this SMS now?')) return;
      const button = form.querySelector('button[type=submit]');
      const result = form.querySelector('.sms-result');
      button.disabled = true; result.textContent = 'Sending...'; result.className = 'sms-result muted small';
      try {
        const response = await fetch('/send-sms', {method:'POST', body:new FormData(form), headers:{Accept:'application/json'}});
        const data = await response.json();
        if (!response.ok || !data.ok) throw new Error(data.error || data.message || 'SMS could not be sent.');
        result.textContent = data.message; result.className = 'sms-result status-ok small';
      } catch (error) { result.textContent = error.message; result.className = 'sms-result status-bad small'; }
      finally { button.disabled = false; }
    }));
    const customMessage = document.getElementById('customMessage');
    if (customMessage) customMessage.addEventListener('input', () => { document.getElementById('customCount').textContent = customMessage.value.length; });
    try {
      const cachedWorkbooks = JSON.parse(sessionStorage.getItem(workbookStatusCacheKey) || 'null');
      if (Array.isArray(cachedWorkbooks) && cachedWorkbooks.length === 2) renderWorkbookStatus(cachedWorkbooks);
    } catch (_) {}
    refreshWorkbookStatus();
    </script></main></body></html>""")
    return "".join(parts)


def parse_multipart(handler: BaseHTTPRequestHandler) -> dict[str, bytes]:
    ctype = handler.headers.get("Content-Type", "")
    length = int(handler.headers.get("Content-Length", "0"))
    body = handler.rfile.read(length)
    raw = (f"Content-Type: {ctype}\r\nMIME-Version: 1.0\r\n\r\n").encode() + body
    msg = BytesParser(policy=default).parsebytes(raw)
    out = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if name:
            out[name] = part.get_payload(decode=True) or b""
    return out


class Handler(BaseHTTPRequestHandler):
    def send_html(self, content: str, status: int = 200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if urllib.parse.urlparse(self.path).path == "/":
            self.send_html(page())
        else:
            self.send_html("Not found", 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/analyze":
            try:
                fields = parse_multipart(self)
                result = analyze_files(fields.get("csv_file", b""), fields.get("xlsx_file", b""))
                ANALYSES[result["analysis_id"]] = result
                self.send_html(page(result))
            except Exception as exc:
                self.send_html(page(error=str(exc)), 400)
        else:
            self.send_html("Not found", 404)

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")


@app.get("/")
def flask_home():
    return page()


@app.get("/health")
def flask_health():
    required = ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_PHONE_NUMBER")
    present = {key: bool(os.environ.get(key)) for key in required}
    configured = all(present.values())
    twilio = False
    if configured:
        try:
            sid = os.environ["TWILIO_ACCOUNT_SID"]
            token = os.environ["TWILIO_AUTH_TOKEN"]
            req = urllib.request.Request(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
                headers={"Authorization": "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode()},
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                twilio = response.status == 200
        except Exception:
            twilio = False
    ok = configured and twilio
    return jsonify({"ok": ok, "configuration": configured, "variables_present": present, "twilio": twilio}), (200 if ok else 503)


@app.post("/analyze")
def flask_analyze():
    try:
        csv_file = request.files.get("csv_file")
        xlsx_file = request.files.get("xlsx_file")
        if not csv_file or not xlsx_file:
            raise ValueError("Both the CSV and Excel workbook are required.")
        result = analyze_files(csv_file.read(), xlsx_file.read())
        return page(result)
    except Exception as exc:
        return page(error=str(exc)), 400


@app.post("/send-sms")
def flask_send_sms():
    wants_json = "application/json" in request.headers.get("Accept", "")
    if not sms_configured():
        message = "SMS is not fully configured in Vercel."
        return (jsonify({"ok": False, "error": message}), 503) if wants_json else (page(error=message), 503)
    try:
        data = read_signed_payload(request.form.get("payload", ""), request.form.get("signature", ""))
        selected_keys = {
            key.strip() for key in request.form.get("selected_keys", "").split(",") if key.strip()
        }
        recipients = data.get("recipients", [])
        if selected_keys:
            recipients = [recipient for recipient in recipients if str(recipient.get("key") or "") in selected_keys]
        elif request.form.get("selected_keys") is not None:
            raise ValueError("Select at least one employee before sending.")
        mode = request.form.get("message_mode", "automatic")
        custom_message = request.form.get("custom_message", "").strip()
        if mode not in {"automatic", "custom"}:
            raise ValueError("Choose either the automated reminder or custom message option.")
        if mode == "custom" and not custom_message:
            raise ValueError("Type the custom message before sending.")
        if len(custom_message) > 1000:
            raise ValueError("The custom message must be 1,000 characters or fewer.")
        sent = 0
        skipped = 0
        failed = 0
        for recipient in recipients:
            phone = normalize_phone(recipient.get("phone"))
            message = custom_message if mode == "custom" else str(recipient.get("message") or "").strip()
            if not phone:
                skipped += 1
                continue
            try:
                send_twilio_sms(phone, message)
                sent += 1
            except Exception:
                failed += 1
        detail = f"SMS completed: {sent} sent, {skipped} skipped because no valid phone number was found"
        if failed:
            detail += f", and {failed} failed"
        detail += "."
        return jsonify({"ok": failed == 0, "message": detail, "sent": sent, "skipped": skipped, "failed": failed}) if wants_json else page(notice=detail)
    except Exception as exc:
        return (jsonify({"ok": False, "error": str(exc)}), 400) if wants_json else (page(error=str(exc)), 400)


def main():
    url = f"http://{HOST}:{PORT}"
    print(f"Employee Reminder Center is running at {url}")
    print("No Gmail credentials are required. Gmail opens in your signed-in web browser.")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
