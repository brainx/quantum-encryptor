from pathlib import Path

import pytest

from crypto_config import cfg
from ui_helpers import format_key_info_for_display, guess_decrypted_filename


@pytest.mark.parametrize(
    ("input_name", "expected"),
    [
        ("photo_encrypted.pqc", "photo"),
        ("document.txt_encrypted.pqc", "document.txt"),
        ("archive.pqc", "archive_decrypted.bin"),
        ("file_encrypted.txt", "file.txt"),
        ("file.txt", "file_decrypted.txt"),
        (".pqc", "decrypted.bin"),
    ],
)
def test_guess_decrypted_filename(input_name, expected):
    assert guess_decrypted_filename(Path(input_name)) == expected


def test_format_private_key_info_for_display():
    display = format_key_info_for_display(
        {
            "key_type": "private",
            "kem": cfg.KEM_ALG,
            "private_key_format_version": cfg.PEM_PRIVATE_KEY_FORMAT_VERSION,
            "private_key_kdf": cfg.PRIVATE_KEY_KDF_ALG,
        }
    )

    assert display["Key Type"] == "Private"
    assert display["Algorithm"] == cfg.KEM_ALG
    assert display["Password Encrypted"] == "Yes"
    assert display["Private Key Format"] == str(cfg.PEM_PRIVATE_KEY_FORMAT_VERSION)
    assert display["KDF"] == cfg.PRIVATE_KEY_KDF_ALG
