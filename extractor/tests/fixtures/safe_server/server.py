from pathlib import Path

def list_files(directory: str) -> list[str]:
    p = Path(directory)
    return [str(f) for f in p.iterdir() if f.is_file()]
