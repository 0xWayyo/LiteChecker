"""Read the loaded code's version, independently of launcher and working directory."""
from functools import cache
from importlib import metadata
from pathlib import Path
import re
import tomllib


def version_suffix(value: str | None) -> str:
    valid = isinstance(value, str) and len(value) <= 32 and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
    return f" · v{value}" if valid else " · v?"


@cache
def running_version() -> str | None:
    """Source profiles use their own pyproject; wheels use their own metadata."""
    try:
        module = Path(__file__).resolve()
        if module.parent.parent.name == "src":
            project = module.parents[2] / "pyproject.toml"
            with project.open("rb") as stream:
                data = stream.read(65537)
            if len(data) > 65536:
                return None
            info = tomllib.loads(data.decode("utf-8"))["project"]
            if not isinstance(info, dict) or info.get("name") != "litechecker":
                return None
            value = info.get("version")
        else:
            package = metadata.distribution("litechecker")
            # Do not borrow an unrelated installation's metadata on sys.path.
            if Path(package.locate_file("litechecker/app_version.py")).resolve() != module:
                return None
            value = package.version
        return value if version_suffix(value) != " · v?" else None
    except (OSError, ValueError, KeyError, TypeError, metadata.PackageNotFoundError):
        return None
