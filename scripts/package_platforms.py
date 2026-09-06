#!/usr/bin/env python3
"""Build offline production source profiles from an explicit public input allowlist."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import stat
import tomllib
import zipfile

import package_agent
import release
from litechecker.update_store import validate_source_zip

ROOT = Path(__file__).resolve().parents[1]
COMMON_MODULES = (
    "__init__.py", "agent.py", "async_state.py", "atomic_io.py", "cli.py",
    "collector/__init__.py", "collector/auth.py", "collector/db.py",
    "collector/reporting.py", "collector/telegram.py", "config.py",
    "direct_check.py", "direct_network.py", "direct_observation.py", "direct_outbox.py",
    "direct_relay.py", "direct_reporting.py", "direct_service.py", "direct_subscription.py",
    "distribution.py", "maintenance.py", "measurement.py", "models.py", "network_identity.py",
    "platform_security.py", "probe.py", "protocol.py", "runtime.py", "security.py",
    "standalone.py", "state.py", "subscription.py", "telegram_proxy.py", "terminal_ui.py",
    "update_launcher.py", "update_manifest.py", "update_store.py", "updater.py",
)
POSIX_MODULES = ("device_setup.py", "file_safety.py", "native_config.py", "update_host.py", "update_platform.py", "update_service.py")
PLATFORM_MODULES = {
    "windows": ("windows_app.py", "windows_control.py", "windows_diagnostics.py", "windows_doh.py", "windows_job.py", "windows_network.py", "windows_process_state.py", "windows_security.py", "windows_trial.py", "windows_update.py", "windows_worker.py"),
    "macos": POSIX_MODULES + ("install_handoff.py", "macos_network.py", "macos_service.py", "macos_update.py", "native_install.py", "native_runtime.py"),
    "linux": POSIX_MODULES + ("linux_update.py",),
}
POSIX_FILES = ("run.sh", "scripts/install.sh", "scripts/control.sh", "scripts/update.sh", "scripts/install-profile.sh")
PLATFORM_FILES = {
    "windows": ("LiteChecker.bat", "WINDOWS.md", "scripts/windows-native.ps1", "scripts/windows-app-entry.py", "scripts/windows-entry.py"),
    "macos": POSIX_FILES + ("INSTALL.command", "MACOS.md", "scripts/install-macos.sh", "scripts/native-direct.sh"),
    "linux": POSIX_FILES + ("INSTALL.sh", "LINUX.md", "Dockerfile", ".dockerignore", "compose.standalone.yml", "compose.telegram-proxy.yml", "scripts/prepare-updater.sh"),
}
# psutil is required by shared probe.py, including POSIX: it is not Windows-only.
RUNTIME_DEPENDENCIES = (
    "cryptography==50.0.1", "dnspython==2.8.0", "filelock==3.32.4",
    "httpx[socks]>=0.28,<1", "psutil==7.1.3", "pydantic>=2.10,<3",
)
# Exact transitive lock allowlist; wheels retain original pins and hashes.
RUNTIME_PACKAGES = frozenset({
    "annotated-types", "anyio", "certifi", "cffi", "cryptography", "dnspython",
    "filelock", "h11", "httpcore", "httpx", "idna", "litechecker", "psutil",
    "pycparser", "pydantic", "pydantic-core", "socksio", "typing-extensions", "typing-inspection",
})


def source_name(platform: str, version: str) -> str:
    labels = {"windows": "windows-update-source", "macos": "macOS", "linux": "Linux"}
    return f"LiteChecker-{version}-{labels[platform]}.zip"


def _read(name: str) -> bytes:
    # Reuse regular-file, no-link traversal; never invoke legacy secret packaging.
    return package_agent._read_release_input(ROOT / name, root=ROOT)


def _runtime_metadata(version: str) -> dict[str, bytes]:
    source = tomllib.loads(_read("pyproject.toml").decode())
    if source["project"]["version"] != version:
        raise ValueError("source project version does not match requested release")
    if tuple(source["project"]["dependencies"]) != RUNTIME_DEPENDENCIES:
        raise ValueError("runtime dependency allowlist needs review")
    project = (
        '[project]\nname = "litechecker"\nversion = ' + json.dumps(version) + '\n'
        'description = "LiteChecker platform runtime"\nrequires-python = ">=3.12"\n'
        'dependencies = ' + json.dumps(list(RUNTIME_DEPENDENCIES)) + '\n\n'
        '[project.scripts]\nlitechecker = "litechecker.cli:main"\n\n'
        '[build-system]\nrequires = ["hatchling>=1.27"]\nbuild-backend = "hatchling.build"\n\n'
        '[tool.hatch.build.targets.wheel]\npackages = ["src/litechecker"]\nonly-packages = true\n'
    ).encode()
    lock_text = _read("uv.lock").decode()
    header, *blocks = lock_text.split("[[package]]\n")
    selected = {}
    for block in blocks:
        record = tomllib.loads("[[package]]\n" + block)["package"][0]
        name = record["name"]
        if name not in RUNTIME_PACKAGES:
            continue
        if name == "litechecker":
            if record["version"] != version:
                raise ValueError("source lock version does not match requested release")
            prefix = block.split("[package.optional-dependencies]", 1)[0]
            metadata = block.split("[package.metadata]\n", 1)[1].split("provides-extras", 1)[0]
            metadata = "\n".join(line for line in metadata.splitlines() if "marker = \"extra ==" not in line)
            block = prefix + "[package.metadata]\n" + metadata + "\n\n"
        selected[name] = block
    if selected.keys() != RUNTIME_PACKAGES:
        raise ValueError("runtime lock allowlist is incomplete")
    lock = (header + "".join("[[package]]\n" + selected[name] for name in sorted(selected))).encode()
    records = tomllib.loads(lock.decode())["package"]
    for record in records:
        dependencies = list(record.get("dependencies", []))
        for extra in record.get("optional-dependencies", {}).values():
            dependencies.extend(extra)
        if any(dep["name"] not in selected for dep in dependencies):
            raise ValueError("runtime lock is missing a dependency")
    return {"pyproject.toml": project, "uv.lock": lock}


def _archive(files: dict[str, bytes]) -> bytes:
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    files = {**files, "CONTENTS.sha256.json": (json.dumps(manifest, indent=2) + "\n").encode()}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            item = zipfile.ZipInfo("LiteChecker/" + name, date_time=(2026, 9, 6, 0, 0, 0))
            item.create_system = 3
            mode = 0o755 if name.endswith((".sh", ".command")) else 0o644
            item.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED)
    return output.getvalue()


def build_sources(output: Path, *, version: str, public_key: bytes, repository: str) -> dict[str, Path]:
    if not release._VERSION.fullmatch(version):
        raise ValueError("invalid release version")
    release._validate_repository(repository)
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("public key must contain 32 bytes")
    # Read the union once: every profile consumes the same immutable byte snapshot.
    names = set(COMMON_MODULES)
    for modules in PLATFORM_MODULES.values():
        names.update(modules)
    snapshot = {"src/litechecker/" + name: _read("src/litechecker/" + name) for name in sorted(names)}
    for files in PLATFORM_FILES.values():
        for name in files:
            if name not in snapshot:
                snapshot[name] = _read(name)
    metadata = _runtime_metadata(version)
    archives = {}
    for platform in PLATFORM_MODULES:
        selected = ["src/litechecker/" + name for name in COMMON_MODULES + PLATFORM_MODULES[platform]]
        files = {name: snapshot[name] for name in selected + list(PLATFORM_FILES[platform])}
        files.update(metadata)
        files["distribution.json"] = (json.dumps({"schema": 1, "platform": platform}, sort_keys=True, separators=(",", ":")) + "\n").encode()
        files["update-channel.json"] = release._channel_bytes(base64.b64encode(public_key).decode(), repository, platform=platform)
        if platform == "linux":
            # The repository's collector Dockerfile stays unchanged; the client image has no server extra.
            files["Dockerfile"] = files["Dockerfile"].replace(b" --extra collector", b"")
        data = _archive(files)
        validate_source_zip(data, expected_platform=platform, expected_version=version)
        archives[platform] = data
    output = release._path(output)
    output.mkdir(parents=True, exist_ok=True)
    paths = {platform: output / source_name(platform, version) for platform in archives}
    release._write_new_files({paths[platform]: (data, 0o644) for platform, data in archives.items()})
    return paths


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args(argv)
    key = base64.b64decode(release._read_file(args.public_key, limit=128).strip(), validate=True)
    paths = build_sources(args.output, version=args.version, public_key=key, repository=args.repository)
    for path in paths.values():
        print(path.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
