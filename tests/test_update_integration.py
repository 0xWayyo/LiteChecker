"""Author-produced signed artifacts pass through the real transactional updater."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import zipfile

import pytest


@pytest.mark.asyncio
async def test_signed_author_release_updates_rolls_back_and_bounds_storage(tmp_path):
    from litechecker.updater import check_for_update, initialize_channel

    script = Path(__file__).resolve().parents[1] / "scripts/release.py"
    spec = importlib.util.spec_from_file_location("integration_author", script)
    author = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(author)
    author_root, root = tmp_path / "author", tmp_path / "device"
    author_root.mkdir()
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="litechecker"\nversion="0.1.0"\n')
    private, public = author_root / "private.key", author_root / "public.key"
    author.keygen(private, public)
    device = root / "state/device.json"
    device.parent.mkdir()
    device.write_bytes(b"preserved device identity")

    class Adapter:
        baseline = root
        maintenance_lock = root / "state/maintenance.lock"
        fail_version = "0.5.0"
        active = root
        activations = []

        async def prepare(self, release):
            assert (release / "src/litechecker/__init__.py").is_file()

        async def is_running(self):
            return False

        async def activate(self, release, running):
            assert running is False, "stopped tester must never be started"
            self.active = release
            self.activations.append(release.name)

        async def healthy(self, release, running):
            return release.name != self.fail_version and self.active == release

    adapter = Adapter()
    for sequence, version in enumerate(("0.2.0", "0.3.0", "0.4.0", "0.5.0"), 2):
        files = {
            "pyproject.toml": f'[project]\nname="litechecker"\nversion="{version}"\n'.encode(),
            "src/litechecker/__init__.py": b"# synthetic release\n",
        }
        manifest = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        files["CONTENTS.sha256.json"] = json.dumps(manifest).encode()
        archive = author_root / f"input-{version}.zip"
        with zipfile.ZipFile(archive, "w") as output:
            for name, data in files.items():
                entry = zipfile.ZipInfo("LiteChecker/" + name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                output.writestr(entry, data)
        published = author_root / version
        author.build_release(archive=archive, private_key=private, output=published,
                             version=version, sequence=str(sequence), repository="fixture/LiteChecker")
        channel = (published / "update-channel.json").read_bytes()
        assert initialize_channel(root, channel) is (sequence == 2)
        metadata = (published / "release.json").read_bytes()
        urls = json.loads(metadata)["payload"]["artifact"]["urls"]
        responses = {json.loads(channel)["manifest_urls"][0]: metadata,
                     urls[0]: (published / f"LiteChecker-{version}.zip").read_bytes()}

        async def fetch(url, limit):
            data = responses[url]
            assert len(data) <= limit
            return data

        result = await check_for_update(root, adapter, force=True, fetcher=fetch)
        assert result["status"] == ("rolled-back" if version == "0.5.0" else "updated")
        assert device.read_bytes() == b"preserved device identity"

    assert adapter.active.name == "0.4.0"
    assert result["version"] == "0.4.0"
    assert result["previous"] == "0.3.0"
    assert sorted(item.name for item in (root / ".updates/releases").iterdir()) == ["0.3.0", "0.4.0"]
    assert not list((root / ".updates/tmp").iterdir())
