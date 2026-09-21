"""PSEUDOCODE: PDF chunking.

This file is a design sketch, not executable application code.
"""

# pyright: reportUndefinedVariable=false


def inspect_pdf(path, settings):
    # Sadece PDF ve config'teki maksimum boyuta izin ver.
    require(path.lower().endswith(".pdf"))
    size = file_size(path)
    require(size <= settings.transfer.max_file_size_bytes)
    return FileInfo(path=path, size=size, sha256=sha256_file(path))


def read_chunks(path, chunk_size):
    # Buyuk dosyayi tek seferde RAM'e yuklemek yerine parca parca oku.
    with open(path, "rb") as file:
        sequence = 0
        while chunk := file.read(chunk_size):
            yield Chunk(sequence=sequence, payload=chunk)
            sequence += 1
