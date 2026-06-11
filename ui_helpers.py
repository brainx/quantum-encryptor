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


def format_key_info_for_display(key_info: dict[str, object]) -> dict[str, str]:
    """Format strict key-inspection metadata for Streamlit display."""
    display = {
        "Key Type": str(key_info["key_type"]).title(),
        "Algorithm": str(key_info["kem"]),
    }
    if key_info.get("key_type") == "private":
        display["Password Encrypted"] = "Yes"
        display["Private Key Format"] = str(key_info.get("private_key_format_version", "Unknown"))
        display["KDF"] = str(key_info.get("private_key_kdf", "Unknown"))
    return display
