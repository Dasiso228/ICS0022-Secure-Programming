import argparse
import os
import resource
import sys

from cryptography.exceptions import UnsupportedAlgorithm

from .auth import require_terminal
from .crypto import encrypt_vault
from .storage import locked_storage
from .validation import VaultError, entry_id
from .vault import add_entry, initialize, unlocked


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid command or arguments. Use --help.\n")


def parser():
    result = SafeParser(description="Local password manager: Checkpoint 2.")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create a vault")
    commands.add_parser("add", help="Add an encrypted entry")
    commands.add_parser("list", help="List entry IDs and labels")
    show = commands.add_parser("show", help="View an entry with its password hidden")
    show.add_argument("entry_id", metavar="ENTRY_ID")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "show":
            entry_id(args.entry_id)
        require_terminal()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        with locked_storage(create=args.command == "init") as storage:
            if args.command == "init":
                initialize(storage)
                print("Vault created.")
                return 0
            with unlocked(storage) as (payload, key, salt):
                if args.command == "add":
                    identifier = add_entry(payload)
                    storage.save(encrypt_vault(payload, key, salt))
                    print(f"Entry added: {identifier}")
                elif args.command == "list":
                    if not payload["entries"]:
                        print("Vault is empty.")
                    for entry in payload["entries"]:
                        print(f"{entry['id']}  {entry['label']}")
                else:
                    entry = next(
                        (item for item in payload["entries"] if item["id"] == args.entry_id),
                        None,
                    )
                    if entry is None:
                        raise VaultError("Entry not found.")
                    for field in ("id", "label", "username", "notes"):
                        print(f"{field.capitalize()}: {entry[field]}")
                    print("Password: [hidden]")
        return 0
    except VaultError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nOperation interrupted; check vault state before retrying.", file=sys.stderr)
        return 130
    except UnsupportedAlgorithm:
        print("Error: the cryptographic backend does not support the required scheme.", file=sys.stderr)
        return 1
    except (OSError, MemoryError):
        print("Error: a system operation failed; check vault state before retrying.", file=sys.stderr)
        return 1
    except Exception:
        print("Error: operation failed; success was not confirmed.", file=sys.stderr)
        return 1
