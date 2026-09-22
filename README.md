# CLI Password Manager

Secure Programming, ICS0022. Checkpoint 1: threat model and architecture.

## Project scope

The project will be a local command-line password manager for one user on
Linux and macOS. The user will protect a vault with a master password and
manage entries containing a label, username, password and optional note.
The planned vault location is `~/.securepm/vault.json`.

The initial version will support creating a vault, adding, listing, viewing,
editing and deleting entries, changing the master password and generating
passwords. Each command that accesses an existing vault will require the
master password. Cloud synchronisation, shared accounts, a web interface
and password recovery are outside the initial scope.

## Checkpoint 1 status

This checkpoint contains only the README and the design document in 
PDF formats. The architecture, threat model, vault format and cryptographic
scheme are proposed decisions. Application code has not been implemented.
The commands and setup below describe the intended implementation for the
next checkpoint and cannot run as a password manager yet.

## Planned technology

- Python 3.12 or newer for the CLI and application logic.
- The cryptography library for Argon2id key derivation and AES-256-GCM encryption.
- Python standard-library modules for argument parsing, hidden password input,
  secure random generation, JSON, file operations and locking.
- One encrypted JSON vault in a private directory, with no plaintext passwords
  or encryption keys stored on disk.

The design separates user management, encryption and storage. Python keeps
the project small and readable, while the cryptography library provides the
cryptographic operations. The tested dependency version will be pinned when
implementation begins.

## Planned commands

The intended command prefix is `.venv/bin/python -m password_manager`.

| Command | Planned behaviour |
| --- | --- |
| `init` | Choose and confirm a master password; create a vault without overwriting an existing one. |
| `add` | Unlock the vault and prompt for a new entry. |
| `list` | Unlock and list entry IDs and labels without passwords. |
| `show ENTRY_ID` | Unlock and intentionally reveal the selected entry in a terminal. |
| `update ENTRY_ID` | Unlock, prompt for changes and save an entry. |
| `delete ENTRY_ID` | Unlock and require confirmation before deletion. |
| `change-master` | Unlock with the old password and re-encrypt with a confirmed new password. |
| `generate --length 20` | Generate a random password; default length 20, allowed range 12 to 128. |

Entry fields and passwords will be entered through prompts, not command-line
arguments. An entry ID will be a UUID in 32-character hexadecimal form.
Password generation will not require an existing vault.

## Planned build and run

Python does not require a separate compilation step. After the application
is implemented, the intended setup from the repository root on Linux or macOS is:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
.venv/bin/python -m password_manager --help
.venv/bin/python -m password_manager init
```

These are future run instructions. There is currently no password_manager
package, so the last two commands will not work at Checkpoint 1.
The application will run as the ordinary user without sudo.

## Design document

The document in `pdf` contains the architecture diagram, threats and intended
mitigations, the proposed vault format and encryption scheme, memory-handling
limits and the plan for safe file operations.

