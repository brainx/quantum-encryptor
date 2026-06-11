from pathlib import Path

import pytest

from ui_helpers import guess_decrypted_filename


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
