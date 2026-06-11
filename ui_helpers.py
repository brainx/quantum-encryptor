from pathlib import Path


def guess_decrypted_filename(encrypted_filename: Path) -> str:
    """Suggest a local filename for decrypted output."""
    if encrypted_filename.name == ".pqc":
        return "decrypted.bin"
    stem = encrypted_filename.stem
    suffix = encrypted_filename.suffix
    if suffix == ".pqc":
        if stem.endswith("_encrypted"):
            clean_stem = stem[: -len("_encrypted")]
            return clean_stem or "decrypted.bin"
        return f"{stem}_decrypted.bin"
    if stem.endswith("_encrypted"):
        clean_stem = stem[: -len("_encrypted")]
        return f"{clean_stem or 'decrypted'}{suffix}"
    return f"{stem}_decrypted{suffix or '.bin'}"
