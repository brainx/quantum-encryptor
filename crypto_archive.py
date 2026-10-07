"""Bounded directory archives; encryption remains the responsibility of crypto_stream."""

import contextlib
import ctypes
import errno
import io
import os
from pathlib import Path
import secrets
import stat
import struct
import sys
import unicodedata
import zipfile
from dataclasses import dataclass
from typing import BinaryIO, Callable, Iterator, cast

from crypto_config import cfg
from crypto_core import CryptoCoreError

MAX_ARCHIVE_ENTRIES = 10_000
MAX_CENTRAL_DIRECTORY_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_PATH_BYTES = 1024
MAX_ARCHIVE_DEPTH = 32
Cancelled = Callable[[], bool] | None
_EOCD = struct.Struct("<4s4H2IH")
_CENTRAL = struct.Struct("<4s6H3I5H2I")
_LOCAL = struct.Struct("<4s5H3I2H")


class ArchiveError(CryptoCoreError):
    """An archive or directory cannot be processed safely."""


class ArchiveCancelledError(ArchiveError):
    """The caller cancelled an archive operation before publication."""


class ArchiveDurabilityError(ArchiveError):
    """The restored directory was published, but directory fsync failed."""


@dataclass(frozen=True)
class ArchiveSummary:
    files: int
    directories: int
    bytes: int


@dataclass(frozen=True)
class _SourceEntry:
    parts: tuple[str, ...]
    name: str
    metadata: os.stat_result
    directory: bool


def _checkpoint(cancelled: Cancelled) -> None:
    if cancelled is not None and cancelled():
        raise ArchiveCancelledError("Archive operation cancelled.")


def _validate_limit(limit: int) -> None:
    if type(limit) is not int or not 0 <= limit <= cfg.MAX_STREAM_FILE_BYTES:
        raise ArchiveError("Invalid archive size limit.")


def _portable_name(name: str, *, normalize: bool = False) -> str:
    normalized = unicodedata.normalize("NFC", name)
    if not normalize and normalized != name:
        raise ArchiveError("Archive paths must use canonical Unicode names.")
    parts = normalized.split("/")
    try:
        invalid = len(normalized.encode("utf-8")) > MAX_ARCHIVE_PATH_BYTES
        for part in parts:
            stem = part.split(".", 1)[0].upper()
            invalid |= (
                part in {"", ".", ".."}
                or part.endswith((" ", "."))
                or len(part.encode("utf-8")) > 255
                or any(ord(char) < 32 or ord(char) == 127 or char in '\\<>:"|?*' for char in part)
                or stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
                or stem
                in {f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789\u00b9\u00b2\u00b3"}
            )
    except UnicodeEncodeError as exc:
        raise ArchiveError("Archive paths must be valid UTF-8 text.") from exc
    if invalid or len(parts) > MAX_ARCHIVE_DEPTH:
        raise ArchiveError("Archive contains an unsupported or nonportable path.")
    return normalized


def _register_path(paths: dict[str, tuple[str, bool, bool]], name: str, directory: bool) -> None:
    parts = name.split("/")
    for index in range(1, len(parts) + 1):
        prefix = "/".join(parts[:index])
        explicit = index == len(parts)
        is_directory = directory if explicit else True
        key = prefix.casefold()
        previous = paths.get(key)
        if previous is not None:
            old_name, old_directory, old_explicit = previous
            if old_name != prefix or old_directory != is_directory or (explicit and old_explicit):
                raise ArchiveError("Archive contains colliding paths.")
            explicit |= old_explicit
        paths[key] = (prefix, is_directory, explicit)
        if len(paths) > MAX_ARCHIVE_ENTRIES:
            raise ArchiveError("Archive contains too many files or directories.")


def _directory_flags() -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ArchiveError("Directory archives require supported POSIX filesystem operations.")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@contextlib.contextmanager
def _directory(path: Path) -> Iterator[int]:
    absolute = path.absolute()
    if ".." in absolute.parts:
        raise ArchiveError("Parent traversal is not allowed.")
    flags = _directory_flags()
    fd = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


@contextlib.contextmanager
def _relative_directory(root_fd: int, parts: tuple[str, ...]) -> Iterator[int]:
    fd = os.dup(root_fd)
    try:
        for component in parts:
            next_fd = os.open(component, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def _unchanged(before: os.stat_result, after: os.stat_result) -> bool:
    return all(
        getattr(before, field) == getattr(after, field)
        for field in ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _inventory(root_fd: int, limit: int, cancelled: Cancelled) -> list[_SourceEntry]:
    entries: list[_SourceEntry] = []
    paths: dict[str, tuple[str, bool, bool]] = {}
    total = 0

    def scan(fd: int, parts: tuple[str, ...]) -> None:
        nonlocal total
        with os.scandir(fd) as children:
            for child in children:
                _checkpoint(cancelled)
                original_parts = (*parts, child.name)
                name = _portable_name("/".join(original_parts), normalize=True)
                metadata = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                directory = stat.S_ISDIR(metadata.st_mode)
                if not directory and not stat.S_ISREG(metadata.st_mode):
                    raise ArchiveError("Directory backups accept only regular files and directories.")
                _register_path(paths, name, directory)
                entries.append(_SourceEntry(original_parts, name, metadata, directory))
                if directory:
                    with _relative_directory(fd, (child.name,)) as child_fd:
                        if not _unchanged(metadata, os.fstat(child_fd)):
                            raise ArchiveError("Source directory changed during backup.")
                        scan(child_fd, original_parts)
                else:
                    total += metadata.st_size
                    if total > limit:
                        raise ArchiveError("Directory content exceeds the archive size limit.")

    scan(root_fd, ())
    return sorted(entries, key=lambda entry: entry.name)


def _write_all(sink: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = sink.write(view)
        if written is None or not 0 < written <= len(view):
            raise OSError("Archive output could not be written completely.")
        view = view[written:]


class _BoundedWriter:
    def __init__(self, target: BinaryIO, limit: int, cancelled: Cancelled):
        self.target, self.limit, self.cancelled = target, limit, cancelled

    def write(self, data: bytes) -> int:
        _checkpoint(self.cancelled)
        if self.target.tell() + len(data) > self.limit:
            raise ArchiveError("Archive exceeds the size limit, including metadata.")
        _write_all(self.target, data)
        return len(data)

    def tell(self) -> int:
        return self.target.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.target.seek(offset, whence)

    def flush(self) -> None:
        self.target.flush()


def pack_directory(
    source: Path, archive: BinaryIO, *, max_archive_bytes: int = cfg.MAX_STREAM_FILE_BYTES, cancelled: Cancelled = None
) -> ArchiveSummary:
    """Write a bounded ZIP_STORED snapshot of a regular-file directory tree."""
    _validate_limit(max_archive_bytes)
    _checkpoint(cancelled)
    with _directory(source) as root_fd:
        root_metadata = os.fstat(root_fd)
        entries = _inventory(root_fd, max_archive_bytes, cancelled)
        try:
            archive_fd = archive.fileno()
        except (AttributeError, io.UnsupportedOperation):
            pass
        else:
            output_metadata = os.fstat(archive_fd)
            if any(
                (entry.metadata.st_dev, entry.metadata.st_ino) == (output_metadata.st_dev, output_metadata.st_ino)
                for entry in entries
            ):
                raise ArchiveError("Archive output must be separate from every source file.")
        archive.seek(0)
        archive.truncate()
        writer = _BoundedWriter(archive, max_archive_bytes, cancelled)
        # ZipFile needs only write/seek/tell/flush from this bounded adapter.
        with zipfile.ZipFile(cast(BinaryIO, writer), "w", compression=zipfile.ZIP_STORED, allowZip64=False) as output:
            for entry in entries:
                _checkpoint(cancelled)
                info = zipfile.ZipInfo(entry.name + ("/" if entry.directory else ""))
                info.create_system = 3
                info.external_attr = ((stat.S_IFDIR | 0o700) if entry.directory else (stat.S_IFREG | 0o600)) << 16
                if entry.directory:
                    info.external_attr |= 0x10
                    output.writestr(info, b"")
                    continue
                with _relative_directory(root_fd, entry.parts[:-1]) as parent_fd:
                    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
                    fd = os.open(entry.parts[-1], flags, dir_fd=parent_fd)
                    with os.fdopen(fd, "rb", buffering=0) as input_file:
                        if not _unchanged(entry.metadata, os.fstat(input_file.fileno())):
                            raise ArchiveError("Source file changed during backup.")
                        count = 0
                        with output.open(info, "w") as member:
                            while data := input_file.read(cfg.STREAM_CHUNK_BYTES):
                                _checkpoint(cancelled)
                                count += len(data)
                                if count > entry.metadata.st_size:
                                    raise ArchiveError("Source file changed during backup.")
                                _write_all(cast(BinaryIO, member), data)
                        if count != entry.metadata.st_size or not _unchanged(
                            entry.metadata, os.fstat(input_file.fileno())
                        ):
                            raise ArchiveError("Source file changed during backup.")
                        if not _unchanged(
                            entry.metadata, os.stat(entry.parts[-1], dir_fd=parent_fd, follow_symlinks=False)
                        ):
                            raise ArchiveError("Source file changed during backup.")
            for entry in entries:
                if entry.directory:
                    with _relative_directory(root_fd, entry.parts) as fd:
                        if not _unchanged(entry.metadata, os.fstat(fd)):
                            raise ArchiveError("Source directory changed during backup.")
            if not _unchanged(root_metadata, os.fstat(root_fd)):
                raise ArchiveError("Source directory changed during backup.")
        _checkpoint(cancelled)
    archive.seek(0)
    return inspect_archive(archive, max_archive_bytes=max_archive_bytes, cancelled=cancelled)


def _read_exact(archive: BinaryIO, size: int) -> bytes:
    parts = bytearray()
    while len(parts) < size:
        chunk = archive.read(size - len(parts))
        if not chunk:
            raise ArchiveError("Archive is truncated.")
        parts.extend(chunk)
    return bytes(parts)


def _preflight_directory(archive: BinaryIO, limit: int) -> tuple[int, int]:
    archive.seek(0, os.SEEK_END)
    size = archive.tell()
    if not _EOCD.size <= size <= limit:
        raise ArchiveError("Archive is empty, truncated, or exceeds the size limit.")
    archive.seek(-_EOCD.size, os.SEEK_END)
    signature, disk, central_disk, disk_count, count, central_size, central_offset, comment = _EOCD.unpack(
        _read_exact(archive, _EOCD.size)
    )
    if (
        signature != b"PK\x05\x06"
        or disk
        or central_disk
        or comment
        or disk_count != count
        or count > MAX_ARCHIVE_ENTRIES
        or central_size > MAX_CENTRAL_DIRECTORY_BYTES
        or central_offset + central_size != size - _EOCD.size
    ):
        raise ArchiveError("Unsupported archive directory; ZIP64 and comments are not supported.")
    # Bound and count records before ZipFile allocates its directory and ZipInfo objects.
    archive.seek(central_offset)
    directory = _read_exact(archive, central_size)
    offset = observed = 0
    while offset < len(directory):
        if offset + _CENTRAL.size > len(directory):
            raise ArchiveError("Malformed archive directory.")
        fields = _CENTRAL.unpack_from(directory, offset)
        if fields[0] != b"PK\x01\x02":
            raise ArchiveError("Malformed archive directory.")
        offset += _CENTRAL.size + fields[10] + fields[11] + fields[12]
        observed += 1
        if observed > MAX_ARCHIVE_ENTRIES:
            raise ArchiveError("Archive contains too many entries.")
    if offset != len(directory) or observed != count:
        raise ArchiveError("Archive directory count is inconsistent.")
    return count, central_offset


@contextlib.contextmanager
def _validated_archive(
    archive: BinaryIO, limit: int, cancelled: Cancelled
) -> Iterator[tuple[zipfile.ZipFile, ArchiveSummary]]:
    _validate_limit(limit)
    _checkpoint(cancelled)
    count, central_offset = _preflight_directory(archive, limit)
    try:
        with zipfile.ZipFile(archive, "r") as source:
            infos = source.infolist()
            if len(infos) != count:
                raise ArchiveError("Archive directory count is inconsistent.")
            paths: dict[str, tuple[str, bool, bool]] = {}
            offset = total = files = 0
            for info in infos:
                _checkpoint(cancelled)
                name = _portable_name(info.filename[:-1] if info.is_dir() else info.filename)
                _register_path(paths, name, info.is_dir())
                file_type = stat.S_IFMT(info.external_attr >> 16)
                if (
                    info.orig_filename != info.filename
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.compress_size != info.file_size
                    or info.flag_bits & ~0x800
                    or info.extra
                    or info.comment
                    or info.volume
                    or info.extract_version > 20
                    or info.create_system not in {0, 3}
                    or info.header_offset != offset
                    or file_type not in ({0, stat.S_IFDIR} if info.is_dir() else {0, stat.S_IFREG})
                    or (info.is_dir() and info.file_size != 0)
                ):
                    raise ArchiveError("Archive contains an unsupported entry.")
                archive.seek(offset)
                local = _LOCAL.unpack(_read_exact(archive, _LOCAL.size))
                encoded_name = info.filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
                if (
                    local[0] != b"PK\x03\x04"
                    or local[1] > 20
                    or local[2] != info.flag_bits
                    or local[3] != info.compress_type
                    or local[6] != info.CRC
                    or local[7] != info.compress_size
                    or local[8] != info.file_size
                    or local[9] != len(encoded_name)
                    or local[10] != 0
                    or _read_exact(archive, local[9]) != encoded_name
                ):
                    raise ArchiveError("Archive local metadata is inconsistent.")
                offset += _LOCAL.size + len(encoded_name) + info.file_size
                if offset > central_offset:
                    raise ArchiveError("Archive entries overlap its directory.")
                if not info.is_dir():
                    files += 1
                    total += info.file_size
            if offset != central_offset:
                raise ArchiveError("Archive contains unexpected data.")
            summary = ArchiveSummary(files, sum(directory for _name, directory, _explicit in paths.values()), total)
            # Validate all payloads/CRCs before the caller may create a staging directory.
            for info in infos:
                with source.open(info) as member:
                    while member.read(cfg.STREAM_CHUNK_BYTES):
                        _checkpoint(cancelled)
            _checkpoint(cancelled)
            yield source, summary
    except (zipfile.BadZipFile, UnicodeError, NotImplementedError, struct.error) as exc:
        raise ArchiveError("Archive is malformed or unsupported.") from exc


def inspect_archive(
    archive: BinaryIO, *, max_archive_bytes: int = cfg.MAX_STREAM_FILE_BYTES, cancelled: Cancelled = None
) -> ArchiveSummary:
    """Validate the complete strict ZIP_STORED archive without extracting it."""
    with _validated_archive(archive, max_archive_bytes, cancelled) as (_source, summary):
        return summary


def _publisher() -> Callable[[int, str, int, str], None]:
    _directory_flags()
    library = ctypes.CDLL(None, use_errno=True)
    symbol, flag = ("renameatx_np", 4) if sys.platform == "darwin" else ("renameat2", 1)
    if sys.platform != "darwin" and not sys.platform.startswith("linux"):
        raise ArchiveError("Atomic directory restoration is unsupported on this platform.")
    try:
        function = getattr(library, symbol)
    except AttributeError as exc:
        raise ArchiveError("Atomic directory restoration is unavailable.") from exc
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int

    def publish(source_parent: int, staging: str, destination_parent: int, destination: str) -> None:
        if function(source_parent, os.fsencode(staging), destination_parent, os.fsencode(destination), flag):
            code = ctypes.get_errno()
            if code in {errno.EEXIST, errno.ENOTEMPTY}:
                raise FileExistsError("Restore destination already exists.")
            raise ArchiveError("Could not publish the restored directory without overwriting existing data.")

    return publish


def _make_directories(root_fd: int, parts: tuple[str, ...]) -> None:
    with _relative_directory(root_fd, ()) as first_fd:
        fd = os.dup(first_fd)
        try:
            for component in parts:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                next_fd = os.open(component, _directory_flags(), dir_fd=fd)
                os.close(fd)
                fd = next_fd
                os.fchmod(fd, 0o700)
        finally:
            os.close(fd)


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return stat.S_ISDIR(right.st_mode) and (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _remove_empty_directory(parent_fd: int, name: str, owned: os.stat_result) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if _same_directory(owned, current):
        # Never recurse through this externally visible name, even after an identity check.
        os.rmdir(name, dir_fd=parent_fd)


@contextlib.contextmanager
def _private_directory(parent_fd: int, name: str) -> Iterator[int]:
    os.mkdir(name, 0o700, dir_fd=parent_fd)
    owned = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(owned.st_mode) or owned.st_uid != os.geteuid() or stat.S_IMODE(owned.st_mode) & 0o077:
        raise ArchiveError("Private restore staging directory changed.")
    try:
        with _relative_directory(parent_fd, (name,)) as fd:
            if not _same_directory(owned, os.fstat(fd)):
                raise ArchiveError("Private restore staging directory changed.")
            os.fchmod(fd, 0o700)
            yield fd
    finally:
        _remove_empty_directory(parent_fd, name, owned)


def _remove_contents(fd: int) -> None:
    """Clean owned contents through the held descriptor, even if its name was moved."""
    with os.scandir(fd) as children:
        for child in children:
            metadata = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                with _relative_directory(fd, (child.name,)) as child_fd:
                    if not _same_directory(metadata, os.fstat(child_fd)):
                        raise ArchiveError("Private restore staging directory changed.")
                    _remove_contents(child_fd)
                _remove_empty_directory(fd, child.name, metadata)
            else:
                os.unlink(child.name, dir_fd=fd)


def _sync_tree(fd: int) -> None:
    with os.scandir(fd) as children:
        for child in children:
            if stat.S_ISDIR(os.stat(child.name, dir_fd=fd, follow_symlinks=False).st_mode):
                with _relative_directory(fd, (child.name,)) as directory_fd:
                    _sync_tree(directory_fd)
    os.fsync(fd)


def extract_archive(
    archive: BinaryIO,
    output_directory: Path,
    *,
    max_archive_bytes: int = cfg.MAX_STREAM_FILE_BYTES,
    cancelled: Cancelled = None,
) -> ArchiveSummary:
    """Validate, restore privately, then atomically publish a new directory without replacement."""
    publish = _publisher()
    destination = output_directory.absolute()
    if destination.name in {"", ".", ".."}:
        raise ArchiveError("A new destination directory is required.")
    with _directory(destination.parent) as parent_fd:
        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("Restore destination already exists.")
        with _validated_archive(archive, max_archive_bytes, cancelled) as (source, summary):
            staging = f".pqc-restore.{secrets.token_hex(16)}.tmp"
            published = False
            try:
                # The parent may expose/rename the container name, but its private interior
                # and this held descriptor keep publication independent of that name.
                with _private_directory(parent_fd, staging) as container_fd:
                    with _private_directory(container_fd, "payload") as stage_fd:
                        try:
                            for info in source.infolist():
                                _checkpoint(cancelled)
                                parts = tuple(info.filename.rstrip("/").split("/"))
                                _make_directories(stage_fd, parts if info.is_dir() else parts[:-1])
                                if info.is_dir():
                                    continue
                                with _relative_directory(stage_fd, parts[:-1]) as directory_fd:
                                    fd = os.open(
                                        parts[-1],
                                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                        0o600,
                                        dir_fd=directory_fd,
                                    )
                                    with os.fdopen(fd, "wb", buffering=0) as output, source.open(info) as member:
                                        while data := member.read(cfg.STREAM_CHUNK_BYTES):
                                            _checkpoint(cancelled)
                                            _write_all(output, data)
                                        os.fchmod(output.fileno(), 0o600)
                                        os.fsync(output.fileno())
                            _sync_tree(stage_fd)
                            _checkpoint(cancelled)
                            publish(container_fd, "payload", parent_fd, destination.name)
                            published = True
                        finally:
                            if not published:
                                _remove_contents(stage_fd)
                    os.fsync(container_fd)
                os.fsync(parent_fd)
            except OSError as exc:
                if published:
                    raise ArchiveDurabilityError(
                        "Restored directory was published but durability could not be confirmed."
                    ) from exc
                raise
    return summary
