import secrets
from contextlib import contextmanager
from uuid import uuid4

from .auth import master_password, secret_text
from .crypto import decrypt_vault, derive_key, encrypt_vault
from .validation import FIELD_LIMITS, MAX_ENTRIES, VaultError, text_field, wipe


def initialize(storage):
    if storage.exists():
        raise VaultError("Vault already exists; init cannot overwrite it.")
    master = key = None
    try:
        master = master_password(new=True)
        salt = secrets.token_bytes(16)
        key = derive_key(master, salt)
        storage.create(encrypt_vault({"entries": []}, key, salt))
    finally:
        wipe(master)
        wipe(key)


@contextmanager
def unlocked(storage):
    master = key = payload = None
    try:
        raw = storage.read()
        master = master_password()
        payload, key, salt = decrypt_vault(raw, master)
        wipe(master)
        yield payload, key, salt
    finally:
        wipe(master)
        wipe(key)
        if payload is not None:
            payload["entries"].clear()


def add_entry(payload):
    if len(payload["entries"]) >= MAX_ENTRIES:
        raise VaultError("The vault already contains 500 entries.")
    entry = {"id": uuid4().hex}
    for field, limit in FIELD_LIMITS.items():
        if field == "password":
            entry[field] = secret_text("Entry password: ")
        else:
            value = input(f"{field.capitalize()}: ")
            entry[field] = text_field(value, field, limit, required=field != "notes")
    payload["entries"].append(entry)
    return entry["id"]
