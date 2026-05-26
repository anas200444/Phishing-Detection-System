import os
from typing import Dict, Optional, List, Any
from datetime import datetime, timezone

import firebase_admin
from firebase_admin import credentials, firestore, auth


REPORT_COLLECTIONS: Dict[str, str] = {
    "url": "reported_urls",
    "ip": "reported_ips",
    "phone": "reported_phone_numbers",
    "sms": "reported_sms_content",
    "email": "reported_emails",
}

ALLOWED_REPORT_STATUSES = {
    "pending_review",
    "confirmed_malicious",
    "ignored",
    "false_positive",
    "under_investigation",
}


def init_firestore(service_account_path: Optional[str] = None):
    if firebase_admin._apps:
        return firestore.client()

    service_account_path = (
        service_account_path
        or os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH")
        or "serviceAccountKey.json"
    )

    if not os.path.exists(service_account_path):
        raise FileNotFoundError(
            f"Firebase service account file not found: {service_account_path}"
        )

    cred = credentials.Certificate(service_account_path)
    firebase_admin.initialize_app(cred)

    return firestore.client()


def verify_firebase_token(id_token: str) -> Dict[str, Any]:
    init_firestore()

    # Prevent breaking if the frontend passes literal strings from uninitialized JS
    if not id_token or id_token in ("undefined", "null"):
        raise ValueError("Firebase ID token is missing or invalid.")

    try:
        # Provide a 60-second leeway for clock skew between client and server.
        # This prevents the "Token used too early" error if the backend server clock
        # is slightly behind the client's clock when a fresh token is generated.
        decoded = auth.verify_id_token(id_token, clock_skew_seconds=60)
        return decoded
    except TypeError:
        # Fallback if an older version of firebase_admin is installed
        # that doesn't support the clock_skew_seconds parameter.
        try:
            decoded = auth.verify_id_token(id_token)
            return decoded
        except Exception as inner_exc:
            raise ValueError(f"Invalid Firebase token (fallback): {inner_exc}") from inner_exc
    except Exception as exc:
        raise ValueError(f"Invalid Firebase token: {exc}") from exc


def normalize_indicator(indicator_type: str, indicator_value: str) -> str:
    value = indicator_value.strip()

    if indicator_type == "email":
        return value.lower()

    if indicator_type == "phone":
        return (
            value.replace(" ", "")
            .replace("-", "")
            .replace("(", "")
            .replace(")", "")
        )

    if indicator_type == "ip":
        return value.lower()

    if indicator_type == "url":
        return value.rstrip("#")

    return value


def timestamp_to_string(value) -> str:
    if not value:
        return ""

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)


def count_indicator_reports(indicator_value: str, indicator_type: Optional[str] = None) -> int:
    db = init_firestore()

    if indicator_type:
        if indicator_type not in REPORT_COLLECTIONS:
            raise ValueError(
                f"Invalid indicator_type. Use one of: {list(REPORT_COLLECTIONS.keys())}"
            )

        collections_to_search = {
            indicator_type: REPORT_COLLECTIONS[indicator_type]
        }
    else:
        collections_to_search = REPORT_COLLECTIONS

    total = 0

    for current_type, collection_name in collections_to_search.items():
        normalized_value = normalize_indicator(current_type, indicator_value)

        docs = (
            db.collection(collection_name)
            .where("indicator_value", "==", normalized_value)
            .stream()
        )

        total += sum(1 for _ in docs)

    return total


def get_report_risk_level(report_count: int) -> str:
    if report_count >= 10:
        return "high"

    if report_count >= 5:
        return "medium"

    if report_count >= 1:
        return "low"

    return "none"


def get_indicator_report_summary(
    indicator_value: str,
    indicator_type: Optional[str] = None,
):
    count = count_indicator_reports(indicator_value, indicator_type)
    risk_level = get_report_risk_level(count)

    return {
        "indicator_value": indicator_value,
        "indicator_type": indicator_type or "all",
        "report_count": count,
        "report_risk_level": risk_level,
        "is_user_reported": count > 0,
        "is_highly_reported": count >= 10,
    }


def get_collections_to_search(indicator_type: str):
    if indicator_type == "all":
        return REPORT_COLLECTIONS

    if indicator_type not in REPORT_COLLECTIONS:
        raise ValueError(
            f"Invalid indicator_type. Use all or one of: {list(REPORT_COLLECTIONS.keys())}"
        )

    return {indicator_type: REPORT_COLLECTIONS[indicator_type]}


def list_reported_indicators(indicator_type: str = "all") -> List[Dict[str, Any]]:
    db = init_firestore()
    collections_to_search = get_collections_to_search(indicator_type)

    reports = []

    for current_type, collection_name in collections_to_search.items():
        docs = (
            db.collection(collection_name)
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .stream()
        )

        for doc in docs:
            data = doc.to_dict() or {}
            indicator_value = data.get("indicator_value", "")

            reports.append({
                "collection_name": collection_name,
                "document_id": doc.id,
                "indicator_type": data.get("indicator_type", current_type),
                "indicator_label": data.get("indicator_label", current_type),
                "indicator_value": indicator_value,
                "original_value": data.get("original_value", indicator_value),
                "report_count": count_indicator_reports(indicator_value, current_type),
                "status": data.get("status", "pending_review"),
                "reported_by": data.get("reported_by", ""),
                "reported_by_email": data.get("reported_by_email", ""),
                "timestamp": timestamp_to_string(data.get("timestamp")),
                "reviewed_by": data.get("reviewed_by", ""),
                "reviewed_by_email": data.get("reviewed_by_email", ""),
                "reviewed_at": timestamp_to_string(data.get("reviewed_at")),
                "review_notes": data.get("review_notes", ""),
                "source": data.get("source", ""),
            })

    return reports


def update_report_status(
    collection_name: str,
    document_id: str,
    new_status: str,
    reviewed_by: str,
    reviewed_by_email: str,
    review_notes: str = "",
) -> Dict[str, Any]:
    if collection_name not in REPORT_COLLECTIONS.values():
        raise ValueError("Invalid report collection name.")

    if new_status not in ALLOWED_REPORT_STATUSES:
        raise ValueError(
            f"Invalid status. Use one of: {sorted(ALLOWED_REPORT_STATUSES)}"
        )

    db = init_firestore()
    doc_ref = db.collection(collection_name).document(document_id)
    doc = doc_ref.get()

    if not doc.exists:
        raise ValueError("Report document not found.")

    doc_ref.update({
        "status": new_status,
        "reviewed_by": reviewed_by,
        "reviewed_by_email": reviewed_by_email,
        "reviewed_at": datetime.now(timezone.utc),
        "review_notes": review_notes.strip(),
    })

    return {
        "collection_name": collection_name,
        "document_id": document_id,
        "status": new_status,
        "reviewed_by": reviewed_by,
        "reviewed_by_email": reviewed_by_email,
    }


def export_reports_csv_rows(indicator_type: str = "all") -> List[Dict[str, Any]]:
    reports = list_reported_indicators(indicator_type)

    rows = []

    for report in reports:
        rows.append({
            "collection_name": report.get("collection_name", ""),
            "document_id": report.get("document_id", ""),
            "indicator_type": report.get("indicator_type", ""),
            "indicator_label": report.get("indicator_label", ""),
            "indicator_value": report.get("indicator_value", ""),
            "report_count": report.get("report_count", 0),
            "status": report.get("status", ""),
            "reported_by": report.get("reported_by", ""),
            "reported_by_email": report.get("reported_by_email", ""),
            "timestamp": report.get("timestamp", ""),
            "reviewed_by": report.get("reviewed_by", ""),
            "reviewed_by_email": report.get("reviewed_by_email", ""),
            "reviewed_at": report.get("reviewed_at", ""),
            "review_notes": report.get("review_notes", ""),
            "source": report.get("source", ""),
        })

    return rows


