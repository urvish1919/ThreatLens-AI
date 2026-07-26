import hashlib
import os
import mimetypes


def calculate_sha256(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def get_file_size(filepath):
    return round(os.path.getsize(filepath) / 1024, 2)


def get_file_type(filepath):
    filetype, _ = mimetypes.guess_type(filepath)

    if filetype is None:
        return "Unknown"

    return filetype