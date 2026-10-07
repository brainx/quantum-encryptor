"""Directory archive boundaries independent of the encryption backend."""

import contextlib
import io
import os
import stat
import struct
import tempfile
import tracemalloc
import unicodedata
import zipfile

import pytest

import crypto_archive as archive


def _zip(entries, *, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as output:
        for name, content in entries:
            output.writestr(name, content)
    stream.seek(0)
    return stream


def _tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "empty").mkdir()
    (source / "nested").mkdir()
    (source / "nested" / "hello.txt").write_bytes(b"hello\x00world")
    (source / "zero.txt").write_bytes(b"")
    (source / "caf\u00e9.txt").write_bytes(b"coffee")
    return source


def _assert_no_stage(parent):
    assert not list(parent.glob(".pqc-restore.*.tmp"))


def test_pack_inspect_restore_preserves_content_empty_directories_and_private_modes(tmp_path):
    source = _tree(tmp_path)
    stream = io.BytesIO()
    expected = archive.ArchiveSummary(3, 2, 17)
    assert archive.pack_directory(source, stream) == expected
    assert archive.inspect_archive(stream) == expected
    with zipfile.ZipFile(stream) as packed:
        assert all(info.compress_type == zipfile.ZIP_STORED for info in packed.infolist())
        assert packed.namelist() == ["caf\u00e9.txt", "empty/", "nested/", "nested/hello.txt", "zero.txt"]
    restored = tmp_path / "restored"
    assert archive.extract_archive(stream, restored) == expected
    for path in source.rglob("*"):
        target = restored / unicodedata.normalize("NFC", str(path.relative_to(source)))
        assert target.is_dir() == path.is_dir()
        if path.is_file():
            assert target.read_bytes() == path.read_bytes()
        assert stat.S_IMODE(target.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
    assert stat.S_IMODE(restored.stat().st_mode) == 0o700
    _assert_no_stage(tmp_path)


def test_empty_directory_round_trip_and_exact_limit(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    stream = io.BytesIO()
    assert archive.pack_directory(source, stream, max_archive_bytes=22) == archive.ArchiveSummary(0, 0, 0)
    assert len(stream.getvalue()) == 22
    archive.extract_archive(stream, tmp_path / "restored", max_archive_bytes=22)
    assert list((tmp_path / "restored").iterdir()) == []
    with pytest.raises(archive.ArchiveError):
        archive.pack_directory(source, io.BytesIO(), max_archive_bytes=21)


def test_pack_normalizes_source_unicode(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "cafe\u0301").mkdir()
    (source / "cafe\u0301" / "re\u0301sume\u0301").write_bytes(b"content")
    stream = io.BytesIO()
    archive.pack_directory(source, stream)
    with zipfile.ZipFile(stream) as output:
        assert output.namelist() == ["caf\u00e9/", "caf\u00e9/r\u00e9sum\u00e9"]


@pytest.mark.parametrize("kind", ["file", "directory", "root", "ancestor", "fifo"])
def test_pack_rejects_links_and_special_files_before_writing(tmp_path, kind):
    source = _tree(tmp_path)
    if kind == "file":
        (source / "link").symlink_to(source / "zero.txt")
    elif kind == "directory":
        (source / "link").symlink_to(source / "nested", target_is_directory=True)
    elif kind == "root":
        alias = tmp_path / "alias"
        alias.symlink_to(source, target_is_directory=True)
        source = alias
    elif kind == "ancestor":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        source = alias / "source"
    else:
        os.mkfifo(source / "fifo")
    stream = io.BytesIO(b"untouched")
    with pytest.raises((archive.ArchiveError, OSError)):
        archive.pack_directory(source, stream)
    assert stream.getvalue() == b"untouched"


def test_pack_rejects_output_alias_without_truncating_source(tmp_path):
    source = _tree(tmp_path)
    original = source / "zero.txt"
    original.write_bytes(b"must survive")
    alias = tmp_path / "alias"
    os.link(original, alias)
    with alias.open("r+b") as stream, pytest.raises(archive.ArchiveError):
        archive.pack_directory(source, stream)
    assert original.read_bytes() == b"must survive"


@pytest.mark.parametrize("mutation", ["replace", "grow", "symlink"])
def test_pack_rejects_source_change_after_inventory(tmp_path, monkeypatch, mutation):
    source = _tree(tmp_path)
    original_inventory = archive._inventory

    def change(*args):
        result = original_inventory(*args)
        target = source / "zero.txt"
        if mutation == "grow":
            target.write_bytes(b"changed")
        else:
            target.unlink()
            if mutation == "replace":
                target.write_bytes(b"")
            else:
                target.symlink_to(source / "nested" / "hello.txt")
        return result

    monkeypatch.setattr(archive, "_inventory", change)
    with pytest.raises((archive.ArchiveError, OSError)):
        archive.pack_directory(source, io.BytesIO())


def test_pack_detects_content_change_while_reading(tmp_path):
    source = _tree(tmp_path)

    class ChangingWriter(io.BytesIO):
        changed = False

        def write(self, data):
            if data == b"coffee":
                self.changed = True
                (source / "caf\u00e9.txt").write_bytes(b"changed content")
            return super().write(data)

    stream = ChangingWriter()
    with pytest.raises(archive.ArchiveError, match="changed"):
        archive.pack_directory(source, stream)
    assert stream.changed


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "/absolute",
        "a/../../escape",
        "a//b",
        "./a",
        "a\\b",
        "C:/file",
        "a:",
        "a?",
        "a.",
        "a ",
        "NUL",
        "COM1.txt",
        "LPT9",
        "COM\u00b9",
        "lpt\u00b2.txt",
        "COM\u00b3.data",
        "a\x01b",
        "a\x7fb",
        "cafe\u0301",
    ],
)
def test_rejects_unsafe_paths_before_creating_stage(tmp_path, name):
    stream = _zip([(name, b"bad")])
    with pytest.raises(archive.ArchiveError):
        archive.extract_archive(stream, tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "names",
    [["a", "a"], ["a", "A"], ["a", "a/b"], ["a/b", "a"], ["a/b", "A/c"], ["a/", "A/"], ["a", "a/"]],
)
def test_rejects_duplicate_casefold_and_prefix_collisions(tmp_path, names):
    with pytest.warns(UserWarning) if names[0] == names[1] else contextlib.nullcontext():
        stream = _zip([(name, b"" if name.endswith("/") else b"content") for name in names])
    with pytest.raises(archive.ArchiveError):
        archive.extract_archive(stream, tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []


def test_implicit_directories_count_and_are_private(tmp_path):
    stream = _zip([("a/b/file", b"data")])
    assert archive.extract_archive(stream, tmp_path / "restored") == archive.ArchiveSummary(1, 2, 4)
    assert (tmp_path / "restored/a/b/file").read_bytes() == b"data"
    assert stat.S_IMODE((tmp_path / "restored/a").stat().st_mode) == 0o700


@pytest.mark.parametrize("file_type", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFSOCK, stat.S_IFDIR])
def test_rejects_special_entry_types_before_staging(tmp_path, file_type):
    info = zipfile.ZipInfo("entry")
    info.create_system = 3
    info.external_attr = (file_type | 0o777) << 16
    stream = _zip([(info, b"target")])
    with pytest.raises(archive.ArchiveError):
        archive.extract_archive(stream, tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "profile",
    [
        "compressed",
        "extra",
        "comment",
        "archive_comment",
        "directory_data",
        "encrypted",
        "descriptor",
        "zip64",
        "trailing_data",
        "prefix",
        "nul",
    ],
)
def test_rejects_unsupported_zip_profiles(tmp_path, profile):
    info = zipfile.ZipInfo("file")
    if profile == "compressed":
        info.compress_type = zipfile.ZIP_DEFLATED
    elif profile == "extra":
        info.extra = b"\x01\x99\x00\x00"
    elif profile == "comment":
        info.comment = b"comment"
    elif profile == "directory_data":
        info.filename = "directory/"
    stream = _zip([(info, b"data")])
    raw = bytearray(stream.getvalue())
    central = raw.index(b"PK\x01\x02")
    if profile in {"encrypted", "descriptor"}:
        flag = 1 if profile == "encrypted" else 8
        struct.pack_into("<H", raw, 6, flag)
        struct.pack_into("<H", raw, central + 8, flag)
    elif profile == "zip64":
        struct.pack_into("<H", raw, 4, 45)
        struct.pack_into("<H", raw, central + 6, 45)
    elif profile == "archive_comment":
        struct.pack_into("<H", raw, len(raw) - 2, 1)
        raw += b"x"
    elif profile == "trailing_data":
        raw += b"x"
    elif profile == "prefix":
        raw = bytearray(b"junk") + raw
    elif profile == "nul":
        raw[30] = 0
        raw[central + 46] = 0
    with pytest.raises(archive.ArchiveError):
        archive.extract_archive(io.BytesIO(raw), tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("nul_offset", [0, 2])
def test_rejects_nul_truncated_names_before_python310_is_dir(monkeypatch, nul_offset):
    raw = bytearray(_zip([("file", b"data")]).getvalue())
    central = raw.index(b"PK\x01\x02")
    raw[30 + nul_offset] = 0
    raw[central + 46 + nul_offset] = 0
    inspected_names = []

    def python310_is_dir(info):
        inspected_names.append(info.filename)
        return info.filename[-1] == "/"

    monkeypatch.setattr(archive.zipfile.ZipInfo, "is_dir", python310_is_dir)
    with pytest.raises(archive.ArchiveError):
        archive.inspect_archive(io.BytesIO(raw))
    assert inspected_names == []


@pytest.mark.parametrize("kind", ["payload", "local_name", "local_size", "overlap", "central_signature", "truncated"])
def test_rejects_corruption_before_staging(tmp_path, kind):
    raw = bytearray(_zip([("file", b"content")]).getvalue())
    central = raw.index(b"PK\x01\x02")
    if kind == "payload":
        raw[34] ^= 1
    elif kind == "local_name":
        raw[30] ^= 1
    elif kind == "local_size":
        struct.pack_into("<I", raw, 22, 100)
    elif kind == "overlap":
        struct.pack_into("<I", raw, central + 42, 1)
    elif kind == "central_signature":
        raw[central] ^= 1
    else:
        del raw[-1]
    with pytest.raises(archive.ArchiveError):
        archive.extract_archive(io.BytesIO(raw), tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("kind", ["count", "central_size", "dishonest_count", "zip64"])
def test_directory_bounds_are_enforced_before_zipfile_allocation(monkeypatch, kind):
    raw = bytearray(_zip([("file", b"content")]).getvalue())
    end = len(raw) - 22
    if kind in {"count", "zip64"}:
        count = 10_001 if kind == "count" else 65_535
        struct.pack_into("<HH", raw, end + 8, count, count)
    elif kind == "dishonest_count":
        struct.pack_into("<HH", raw, end + 8, 0, 0)
    else:
        struct.pack_into("<I", raw, end + 12, archive.MAX_CENTRAL_DIRECTORY_BYTES + 1)

    def forbidden(*_args, **_kwargs):
        pytest.fail("ZipFile must not allocate unbounded/untrusted directory entries")

    monkeypatch.setattr(archive.zipfile, "ZipFile", forbidden)
    with pytest.raises(archive.ArchiveError):
        archive.inspect_archive(io.BytesIO(raw))


def test_limits_include_archive_metadata_and_implicit_directories(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "file").write_bytes(b"payload")
    with pytest.raises(archive.ArchiveError, match="metadata"):
        archive.pack_directory(source, io.BytesIO(), max_archive_bytes=7)
    stream = _zip([("a/b/c", b"payload")])
    with pytest.raises(archive.ArchiveError):
        archive.inspect_archive(stream, max_archive_bytes=len(stream.getvalue()) - 1)
    monkeypatch.setattr(archive, "MAX_ARCHIVE_ENTRIES", 2)
    with pytest.raises(archive.ArchiveError, match="too many"):
        archive.inspect_archive(stream)
    (source / "second").write_bytes(b"")
    (source / "third").write_bytes(b"")
    with pytest.raises(archive.ArchiveError, match="too many"):
        archive.pack_directory(source, io.BytesIO())


@pytest.mark.parametrize("limit", [-1, True, 1.5, 2**40])
def test_invalid_limits_rejected(limit):
    with pytest.raises(archive.ArchiveError, match="limit"):
        archive.inspect_archive(_zip([]), max_archive_bytes=limit)


@pytest.mark.parametrize("name", ["a" * 256, "/".join(["a"] * 33), "/".join(["a" * 100] * 11)])
def test_entry_name_length_and_depth_limits(name):
    with pytest.raises(archive.ArchiveError, match="path"):
        archive.inspect_archive(_zip([(name, b"data")]))


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_restore_never_replaces_existing_destination(tmp_path, kind):
    output = tmp_path / "restored"
    if kind == "directory":
        output.mkdir()
        (output / "keep").write_bytes(b"original")
    elif kind == "file":
        output.write_bytes(b"original")
    else:
        output.symlink_to(tmp_path / "missing")
    with pytest.raises(FileExistsError):
        archive.extract_archive(_zip([("new", b"data")]), output)
    if kind == "directory":
        assert (output / "keep").read_bytes() == b"original"
        assert not (output / "new").exists()
    elif kind == "file":
        assert output.read_bytes() == b"original"
    else:
        assert output.is_symlink()
    _assert_no_stage(tmp_path)


def test_publication_race_does_not_replace_new_destination(tmp_path, monkeypatch):
    output = tmp_path / "restored"
    real_publish = archive._publisher()

    def race(source_parent, staging, destination_parent, destination):
        output.mkdir()
        (output / "keep").write_bytes(b"original")
        real_publish(source_parent, staging, destination_parent, destination)

    monkeypatch.setattr(archive, "_publisher", lambda: race)
    with pytest.raises(FileExistsError):
        archive.extract_archive(_zip([("new", b"data")]), output)
    assert (output / "keep").read_bytes() == b"original"
    assert not (output / "new").exists()
    _assert_no_stage(tmp_path)


def test_restore_parent_swap_remains_anchored_and_does_not_follow_link(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    moved = tmp_path / "original"
    real_publish = archive._publisher()

    def race(source_parent, staging, destination_parent, destination):
        parent.rename(moved)
        parent.symlink_to(outside, target_is_directory=True)
        real_publish(source_parent, staging, destination_parent, destination)

    monkeypatch.setattr(archive, "_publisher", lambda: race)
    archive.extract_archive(_zip([("file", b"content")]), parent / "restored")
    assert list(outside.iterdir()) == []
    assert (moved / "restored/file").read_bytes() == b"content"
    _assert_no_stage(moved)


def test_replaced_stage_name_cannot_substitute_unauthenticated_output(tmp_path, monkeypatch):
    moved = tmp_path / "moved-stage"
    replacement = None
    original_sync = archive._sync_tree

    def substitute(fd):
        nonlocal replacement
        original_sync(fd)
        replacement = next(tmp_path.glob(".pqc-restore.*.tmp"))
        replacement.rename(moved)
        replacement.mkdir()
        (replacement / "unowned").write_bytes(b"must survive")

    monkeypatch.setattr(archive, "_sync_tree", substitute)
    archive.extract_archive(_zip([("file", b"authenticated archive data")]), tmp_path / "restored")
    assert (tmp_path / "restored/file").read_bytes() == b"authenticated archive data"
    assert not (tmp_path / "restored/unowned").exists()
    assert (replacement / "unowned").read_bytes() == b"must survive"
    assert list(moved.iterdir()) == []


def test_failure_after_stage_substitution_cleans_owned_plaintext_only(tmp_path, monkeypatch):
    moved = tmp_path / "moved-stage"
    replacement = None

    def substitute_then_fail(_fd):
        nonlocal replacement
        replacement = next(tmp_path.glob(".pqc-restore.*.tmp"))
        replacement.rename(moved)
        replacement.mkdir()
        (replacement / "unowned").write_bytes(b"must survive")
        raise OSError("test sync failure")

    monkeypatch.setattr(archive, "_sync_tree", substitute_then_fail)
    with pytest.raises(OSError, match="test sync failure"):
        archive.extract_archive(_zip([("file", b"private plaintext")]), tmp_path / "restored")
    assert not (tmp_path / "restored").exists()
    assert (replacement / "unowned").read_bytes() == b"must survive"
    assert list(moved.iterdir()) == []


def test_restore_rejects_symlink_ancestor(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        archive.extract_archive(_zip([("file", b"content")]), alias / "new")
    assert list(outside.iterdir()) == []


def test_cancel_pack_inspect_and_restore_leaves_no_output(tmp_path):
    source = _tree(tmp_path)
    with pytest.raises(archive.ArchiveCancelledError):
        archive.pack_directory(source, io.BytesIO(), cancelled=lambda: True)
    stream = _zip([("file", b"content")])
    with pytest.raises(archive.ArchiveCancelledError):
        archive.inspect_archive(stream, cancelled=lambda: True)
    with pytest.raises(archive.ArchiveCancelledError):
        archive.extract_archive(stream, tmp_path / "restored", cancelled=lambda: True)
    assert not (tmp_path / "restored").exists()
    _assert_no_stage(tmp_path)


def test_cancel_after_staging_cleans_all_partial_plaintext(tmp_path):
    def cancelled():
        return bool(list(tmp_path.glob(".pqc-restore.*.tmp")))

    with pytest.raises(archive.ArchiveCancelledError):
        archive.extract_archive(_zip([("file", b"content")]), tmp_path / "restored", cancelled=cancelled)
    assert list(tmp_path.iterdir()) == []


def test_cancellation_after_plaintext_write_removes_all_staged_content(tmp_path, monkeypatch):
    monkeypatch.setattr(archive.cfg, "STREAM_CHUNK_BYTES", 4)
    partial_was_present = False

    def cancelled():
        nonlocal partial_was_present
        for stage in tmp_path.glob(".pqc-restore.*.tmp"):
            target = stage / "payload/a/file"
            if target.exists() and target.stat().st_size >= 4:
                partial_was_present = True
                return True
        return False

    with pytest.raises(archive.ArchiveCancelledError):
        archive.extract_archive(_zip([("a/file", b"longer content")]), tmp_path / "restored", cancelled=cancelled)
    assert partial_was_present
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failure", ["write", "sync"])
def test_prepublication_io_failure_removes_private_staging(tmp_path, monkeypatch, failure):
    def fail(*_args):
        raise OSError("test disk failure")

    monkeypatch.setattr(archive, "_write_all" if failure == "write" else "_sync_tree", fail)
    with pytest.raises(OSError, match="disk failure"):
        archive.extract_archive(_zip([("a/file", b"content")]), tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failed_directory", ["source", "destination"])
def test_fsync_after_publish_reports_durability_and_preserves_output(tmp_path, monkeypatch, failed_directory):
    original_sync = os.fsync
    parent_stat = tmp_path.stat()

    def fail_after_publish(fd):
        current = os.fstat(fd)
        is_parent = (current.st_dev, current.st_ino) == (parent_stat.st_dev, parent_stat.st_ino)
        after_publish = (tmp_path / "restored").is_dir()
        if after_publish and stat.S_ISDIR(current.st_mode) and is_parent == (failed_directory == "destination"):
            raise OSError("test directory sync failure")
        original_sync(fd)

    monkeypatch.setattr(archive.os, "fsync", fail_after_publish)
    with pytest.raises(archive.ArchiveDurabilityError, match="published"):
        archive.extract_archive(_zip([("file", b"content")]), tmp_path / "restored")
    assert (tmp_path / "restored/file").read_bytes() == b"content"
    _assert_no_stage(tmp_path)


def test_successful_publication_syncs_source_and_destination_directories(tmp_path, monkeypatch):
    real_publish = archive._publisher()
    real_sync = os.fsync
    publication_directories = set()
    synced_after_publish = set()

    def publish(source_parent, staging, destination_parent, destination):
        real_publish(source_parent, staging, destination_parent, destination)
        for fd in (source_parent, destination_parent):
            current = os.fstat(fd)
            publication_directories.add((current.st_dev, current.st_ino))

    def sync(fd):
        real_sync(fd)
        if publication_directories:
            current = os.fstat(fd)
            synced_after_publish.add((current.st_dev, current.st_ino))

    monkeypatch.setattr(archive, "_publisher", lambda: publish)
    monkeypatch.setattr(archive.os, "fsync", sync)
    archive.extract_archive(_zip([("file", b"content")]), tmp_path / "restored")
    assert len(publication_directories) == 2
    assert publication_directories <= synced_after_publish


def test_short_archive_writes_are_completed(tmp_path):
    class ShortWriter(io.BytesIO):
        def write(self, data):
            return super().write(data[:3])

    source = _tree(tmp_path)
    stream = ShortWriter()
    archive.pack_directory(source, stream)
    archive.extract_archive(stream, tmp_path / "restored")
    assert (tmp_path / "restored/nested/hello.txt").read_bytes() == b"hello\x00world"


def test_archive_processing_keeps_payload_memory_bounded(tmp_path, monkeypatch):
    chunk = 64 * 1024
    monkeypatch.setattr(archive.cfg, "STREAM_CHUNK_BYTES", chunk)
    source = tmp_path / "source"
    source.mkdir()
    block = b"x" * chunk
    with (source / "large").open("wb") as output:
        for _ in range(128):
            output.write(block)
    with tempfile.TemporaryFile("w+b") as stream:
        tracemalloc.start()
        try:
            expected = archive.ArchiveSummary(1, 0, 8 * 1024 * 1024)
            assert archive.pack_directory(source, stream) == expected
            assert archive.inspect_archive(stream) == expected
            assert archive.extract_archive(stream, tmp_path / "restored") == expected
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    assert peak < 2 * 1024 * 1024
    with (tmp_path / "restored/large").open("rb") as result:
        for _ in range(128):
            assert result.read(chunk) == block
        assert result.read(1) == b""


def test_unsupported_atomic_rename_fails_before_staging(tmp_path, monkeypatch):
    monkeypatch.setattr(archive.sys, "platform", "unsupported")
    with pytest.raises(archive.ArchiveError, match="unsupported"):
        archive.extract_archive(_zip([]), tmp_path / "restored")
    assert list(tmp_path.iterdir()) == []
