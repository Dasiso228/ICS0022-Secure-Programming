# Checkpoint 2 progress note

Implemented the core CLI password-manager flow: `init`, `add`, `list` and
`show ENTRY_ID`. Each command accessing an existing vault requires the master
password. Entries persist in one encrypted JSON vault across separate runs.

The implementation follows the proposed Argon2id and AES-256-GCM format,
authenticates the header, and stores no separate password verifier. It checks
input and file metadata, uses private file permissions, a persistent advisory
lock, and atomic replacement for updates. Build and run instructions and a
pinned `cryptography` dependency are included in the README.

Checkpoint 2 requires that passwords never be printed in cleartext. Therefore
`show` displays a fixed `[hidden]` marker, overriding the earlier reveal
behaviour proposed in Checkpoint 1. Password input is hidden and fails closed
if the terminal cannot disable echo.

The repository includes 15 automated tests covering the main functional and
security requirements. Run `.venv/bin/python -m unittest discover -s tests -v`


## Local validation record

- OS: Arch Linux; shell: fish.
- Python version: Python 3.14.6.
- cryptography version: 50.0.2.
- Automated tests: 15 tests passed.
- Manual creation, addition, listing and masked viewing: passed.
- Wrong-password rejection and unchanged vault: passed.
- Local Argon2id timing sample: 0.026 seconds.
- macOS validation: not performed.

`update`, `delete`, `change-master`, `generate` and application logging remain
future work from the initial plan. The current checkpoint does not claim full
secure memory erasure, rollback detection, password recovery, or protection
against a compromised operating system.
