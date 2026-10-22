import fcntl
import os
import secrets
import stat
from contextlib import contextmanager, suppress
from pathlib import Path

from .validation import MAX_FILE, VaultError

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
VAULT = "vault.json"


def check_directory(fd, private=False, home=False):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise VaultError("Unsafe directory type.")
    if info.st_uid not in {0, os.getuid()} or info.st_mode & 0o022:
        raise VaultError("Unsafe directory owner or permissions.")
    if (private or home) and info.st_uid != os.getuid():
        raise VaultError("Directory must belong to the current user.")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        raise VaultError("The .securepm directory must have mode 0700.")


def open_home(home):
    path = Path(home).resolve(strict=True)
    fd = os.open(path.anchor, DIR_FLAGS)
    try:
        check_directory(fd)
        for component in path.parts[1:]:
            next_fd = os.open(component, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            check_directory(fd)
        check_directory(fd, home=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def check_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise VaultError("Vault files must be owner-only regular files with one hard link.")


class Storage:
    def __init__(self, directory_fd):
        self.directory_fd = directory_fd

    def open_file(self, name, flags):
        fd = os.open(name, flags | FILE_FLAGS, 0o600, dir_fd=self.directory_fd)
        try:
            check_file(fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def exists(self):
        try:
            os.stat(VAULT, dir_fd=self.directory_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def read(self):
        try:
            fd = self.open_file(VAULT, os.O_RDONLY)
        except FileNotFoundError:
            raise VaultError("No vault found. Run init first.") from None
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise VaultError("Vault file is too large.")
        return raw

    def write_new_file(self, name, raw):
        if len(raw) > MAX_FILE:
            raise VaultError("Vault file is too large.")
        fd = self.open_file(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            with suppress(OSError):
                os.unlink(name, dir_fd=self.directory_fd)
            raise

    def create(self, raw):
        try:
            self.write_new_file(VAULT, raw)
        except FileExistsError:
            raise VaultError("Vault already exists; init cannot overwrite it.") from None
        try:
            os.fsync(self.directory_fd)
        except OSError:
            raise VaultError("Vault was written, but durability could not be confirmed.") from None

    def save(self, raw):
        fd = self.open_file(VAULT, os.O_RDONLY)
        os.close(fd)
        temporary = ".vault-" + secrets.token_hex(16) + ".tmp"
        self.write_new_file(temporary, raw)
        try:
            os.replace(
                temporary, VAULT,
                src_dir_fd=self.directory_fd, dst_dir_fd=self.directory_fd,
            )
            try:
                os.fsync(self.directory_fd)
            except OSError:
                raise VaultError("Vault was replaced, but durability could not be confirmed.") from None
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory_fd)


@contextmanager
def locked_storage(create=False, home=None):
    home_fd = open_home(Path.home() if home is None else home)
    directory_fd = None
    lock_fd = None
    try:
        if create:
            try:
                os.mkdir(".securepm", 0o700, dir_fd=home_fd)
                os.fsync(home_fd)
            except FileExistsError:
                pass
        try:
            directory_fd = os.open(".securepm", DIR_FLAGS, dir_fd=home_fd)
        except FileNotFoundError:
            raise VaultError("No vault found. Run init first.") from None
        check_directory(directory_fd, private=True)
        storage = Storage(directory_fd)
        lock_fd = storage.open_file("vault.lock", os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise VaultError("Vault is busy in another command. Try again later.") from None
        yield storage
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(home_fd)
