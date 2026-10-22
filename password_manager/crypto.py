import base64
import binascii
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .validation import MAX_FILE, VaultError, json_bytes, load_json, validate_payload, wipe

KDF = {"name": "argon2id", "memory_kib": 65536, "passes": 3, "parallelism": 4}


def encode64(value):
    return base64.b64encode(value).decode("ascii")


def decode64(value, size=None):
    if type(value) is not str:
        raise VaultError("Invalid Base64 field.")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise VaultError("Invalid Base64 field.") from None
    if encode64(result) != value or (size is not None and len(result) != size):
        raise VaultError("Invalid Base64 field or length.")
    return result


def derive_key(master, salt):
    key = bytearray(32)
    try:
        Argon2id(
            salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536,
        ).derive_into(master, key)
        return key
    except BaseException:
        wipe(key)
        raise


def parse_outer(raw):
    if len(raw) > MAX_FILE:
        raise VaultError("Vault file is too large.")
    outer = load_json(raw)
    fields = {"version", "kdf", "salt", "nonce", "ciphertext"}
    if type(outer) is not dict or set(outer) != fields:
        raise VaultError("Invalid vault header.")
    if type(outer["version"]) is not int or outer["version"] != 1:
        raise VaultError("Unsupported vault version.")
    settings = outer["kdf"]
    if type(settings) is not dict or set(settings) != set(KDF):
        raise VaultError("Unsupported KDF settings.")
    for name, value in KDF.items():
        if type(settings[name]) is not type(value) or settings[name] != value:
            raise VaultError("Unsupported KDF settings.")
    salt = decode64(outer["salt"], 16)
    nonce = decode64(outer["nonce"], 12)
    ciphertext = decode64(outer["ciphertext"])
    if len(ciphertext) < 16:
        raise VaultError("Invalid ciphertext length.")
    header = {key: value for key, value in outer.items() if key != "ciphertext"}
    return header, salt, nonce, ciphertext


def encrypt_vault(payload, key, salt):
    validate_payload(payload)
    header = {
        "version": 1, "kdf": KDF.copy(), "salt": encode64(salt),
        "nonce": encode64(secrets.token_bytes(12)),
    }
    plaintext = bytearray(json_bytes(payload, ascii_only=False))
    try:
        ciphertext = AESGCM(key).encrypt(
            decode64(header["nonce"], 12), plaintext, json_bytes(header),
        )
        raw = json_bytes({**header, "ciphertext": encode64(ciphertext)})
        if len(raw) > MAX_FILE:
            raise VaultError("Vault file is too large.")
        return raw
    finally:
        wipe(plaintext)


def decrypt_vault(raw, master):
    header, salt, nonce, ciphertext = parse_outer(raw)
    key = derive_key(master, salt)
    plaintext = None
    try:
        plaintext = bytearray(AESGCM(key).decrypt(nonce, ciphertext, json_bytes(header)))
        payload = validate_payload(load_json(plaintext))
        return payload, key, salt
    except InvalidTag:
        wipe(key)
        raise VaultError("Cannot unlock vault: wrong master password or damaged vault.") from None
    except BaseException:
        wipe(key)
        raise
    finally:
        wipe(plaintext)
