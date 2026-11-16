import yaml
from pathlib import Path

def read_settings(path: Path):
    with path.open(encoding="utf-8") as source:
        return yaml.load(source)
