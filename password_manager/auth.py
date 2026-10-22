import getpass
import sys
import warnings

from .validation import VaultError, text_field


def require_terminal():
    if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
        raise VaultError("Use an interactive terminal; redirection is not supported.")


def secret_text(prompt):
    require_terminal()
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            value = getpass.getpass(prompt, stream=sys.stderr)
        except getpass.GetPassWarning:
            raise VaultError("Hidden input is unavailable; operation cancelled.") from None
    return text_field(value, "password", 1024)


def master_password(new=False):
    value = confirmation = None
    try:
        value = secret_text("New master password: " if new else "Master password: ")
        if new:
            if len(value) < 15:
                raise VaultError("Master password must contain at least 15 characters.")
            confirmation = secret_text("Confirm master password: ")
            if value != confirmation:
                raise VaultError("Master passwords do not match.")
        return bytearray(value.encode("utf-8"))
    finally:
        value = confirmation = None
