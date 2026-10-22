# CLI Password Manager

Secure Programming, ICS0022. Checkpoint 2: core requirements implemented.

## Scope and current status

A local command-line password manager for one user. The design targets Linux and
macOS and stores the encrypted vault at `~/.securepm/vault.json`. Each command
accessing an existing vault authenticates again and then exits.

Checkpoint 2 implements creation, addition, listing and masked viewing. Cloud
synchronisation, shared accounts, a web interface and password recovery remain
outside the project scope.

| Command | Current behaviour |
| --- | --- |
| `init` | Confirm a new master password and create a vault without overwriting one. |
| `add` | Authenticate, prompt for an entry and save it encrypted. |
| `list` | Authenticate and print only entry IDs and labels. |
| `show ENTRY_ID` | Authenticate and print metadata; the password is always `[hidden]`. |

The command prefix is `.venv/bin/python -m password_manager`.
Labels, usernames, passwords and notes are entered through prompts. Passwords
are not command arguments. Password input does not echo; the program aborts if
hidden input is unavailable. Vault operations require an interactive terminal.

The original Checkpoint 1 plan proposed revealing passwords with `show`.
Checkpoint 2 explicitly requires an interface that never prints cleartext
passwords, so this implementation masks them. `update`, `delete`,
`change-master` and `generate` are planned but not implemented at this checkpoint.
No application log files are produced at this stage.

## Requirements and setup

Use Python 3.12 or newer, Git and a local POSIX filesystem. Run the application
as the ordinary owner, without `sudo`. The user home and its parent directories
must not be writable by another non-root user. The private `.securepm` directory
must belong to the user and have mode `0700`.

On Arch Linux, install the system packages:

```sh
sudo pacman -Syu --needed python python-pip git
```

On macOS, first install Python 3.12 or newer and Git. macOS is a design target;
native macOS execution has not been verified for this checkpoint.

Clone this repository and open its root directory. Python needs no compilation
step. Create the environment and install the pinned dependency:

```sh
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m password_manager --help
```

These commands also work in fish. Activation is unnecessary because the commands
use the environment's Python directly. For optional fish activation, use
`source .venv/bin/activate.fish`.

## Run

```sh
.venv/bin/python -m password_manager init
.venv/bin/python -m password_manager add
.venv/bin/python -m password_manager list
```

Copy a 32-character ID from `list` and use it instead of `ENTRY_ID`:

```sh
.venv/bin/python -m password_manager show ENTRY_ID
```

A new master password must contain at least 15 characters and at most 1024
UTF-8 bytes. Use a long, unique passphrase. Stored entry passwords must be
nonempty and at most 1024 UTF-8 bytes. Spaces are preserved. The optional note
is a single line. Each command requests the master password independently.

There is no password reset. Do not delete an existing vault to resolve an
error. Repeated `init` refuses to overwrite it.

## Storage and authentication

- `cryptography==50.0.2` supplies Argon2id and AES-256-GCM.
- Argon2id: 32-byte key, random 16-byte salt, 65536 KiB memory, 3 passes, 4 lanes.
- AES-GCM: fresh random 12-byte nonce on every save, full 16-byte tag.
- The entire `entries` payload is encrypted, including IDs, labels, usernames,
  passwords and notes. The outer JSON contains only `version`, `kdf`, `salt`,
  `nonce` and `ciphertext`. Base64 is encoding, not encryption.
- Every header field except `ciphertext` is authenticated as canonical JSON
  associated data. The ciphertext field contains the encrypted payload and tag.
- Successful tag verification authenticates the master-password-derived key.
  No separate password hash, master password or encryption key is stored.
- Invalid headers, duplicate JSON keys, unsupported settings, invalid Base64,
  unexpected fields, excessive sizes and control characters are rejected.
- Wrong passwords or a failed authentication tag reveal no entries and do not
  save changes. Their error message is deliberately the same.
- The directory uses mode `0700`; vault, persistent lock and encrypted temporary
  files use `0600`. Descriptor-based operations reject symlinks, unexpected file
  types and hard links. Entry labels never become paths.
- A persistent advisory lock covers the whole command. Updates sync encrypted
  temporary data before atomic replacement and then sync the directory.

Limits: 8 MiB outer file, 500 entries, 128 UTF-8 bytes per label, 256 per username,
1024 per password, and 4096 per note.

## Tests

```sh
.venv/bin/python -m unittest discover -s tests -v
```

The 15 tests cover encrypted round trips, persistence, wrong passwords, modified
ciphertext and headers, fresh nonces, input limits, permissions, symlinks, hard
links, locking, failed writes, exclusive creation and terminal password masking.
The CLI tests use a pseudo-terminal. They create temporary directories under the
current user's home and remove them afterward; they do not use the real
`~/.securepm` vault. Test credentials are artificial fixtures.

## Limitations and next work

This is a coursework checkpoint, not a security-audited production product.
Mutable key buffers are overwritten and core dumps are disabled for commands,
but CPython cannot guarantee erasure of immutable strings, bytes or library
copies. The application does not protect against root, a debugger, or malware
running as the owner. OS swap and hibernation protection depend on the host.

The lock coordinates cooperating commands. It cannot prevent the owner or an
administrator from modifying files outside the application. An error after
atomic replacement may mean the new file exists but its durability could not
be confirmed; check the vault before retrying. An abrupt process termination
can leave an encrypted temporary file. Rollback to an older valid vault is not
detected. Keeping encrypted backups is the user's responsibility.

The original design PDF remains in the repository's `pdf` directory. See
`CHECKPOINT2.md` for the progress note. Continue committing at meaningful working
milestones and at least once per working session.
