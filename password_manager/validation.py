import json
import re

MAX_FILE = 8 * 1024 * 1024
MAX_ENTRIES = 500
FIELD_LIMITS = {"label": 128, "username": 256, "password": 1024, "notes": 4096}


class VaultError(Exception):
    pass


def wipe(buffer):
    if buffer is not None:
        buffer[:] = b"\x00" * len(buffer)


def text_field(value, field, limit, required=True):
    if type(value) is not str:
        raise VaultError(f"Invalid {field}.")
    if required and not value:
        raise VaultError(f"{field} must not be empty.")
    if not all(character.isprintable() for character in value):
        raise VaultError(f"Control or non-printable characters in {field}.")
    if len(value.encode("utf-8")) > limit:
        raise VaultError(f"{field} exceeds {limit} UTF-8 bytes.")
    return value


def entry_id(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise VaultError("Entry ID must contain 32 lowercase hexadecimal characters.")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VaultError("Duplicate JSON keys.")
        result[key] = value
    return result


def invalid_constant(value):
    raise VaultError("Invalid JSON constant.")


def load_json(data):
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=invalid_constant,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise VaultError("Invalid vault JSON.") from None


def json_bytes(value, ascii_only=True):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=ascii_only, allow_nan=False,
    ).encode("utf-8")


def validate_payload(payload):
    if type(payload) is not dict or set(payload) != {"entries"}:
        raise VaultError("Invalid vault payload.")
    entries = payload["entries"]
    if type(entries) is not list or len(entries) > MAX_ENTRIES:
        raise VaultError("Invalid entry count.")
    seen = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"id", *FIELD_LIMITS}:
            raise VaultError("Invalid entry structure.")
        identifier = entry_id(entry["id"])
        if identifier in seen:
            raise VaultError("Duplicate entry IDs.")
        seen.add(identifier)
        for field, limit in FIELD_LIMITS.items():
            text_field(entry[field], field, limit, required=field != "notes")
    return payload
