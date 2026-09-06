"""Public artifact emission is portable; private-key permissions fail closed."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def release():
    script = Path(__file__).resolve().parents[1] / "scripts/release.py"
    spec = importlib.util.spec_from_file_location("release_writer", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("without_fchmod", [False, True])
def test_public_artifacts_write_exclusively_on_host_and_without_fchmod(
    release, tmp_path, monkeypatch, without_fchmod,
):
    if without_fchmod:
        monkeypatch.delattr(release.os, "fchmod", raising=False)
    archive, metadata = tmp_path / "source.zip", tmp_path / "release.json"
    outputs = {archive: (b"public archive", 0o644), metadata: (b"public metadata", 0o644)}
    release._write_new_files(outputs)
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == {
        "source.zip": b"public archive", "release.json": b"public metadata",
    }
    with pytest.raises(release.ReleaseError, match="output-exists"):
        release._write_new_files({archive: (b"replacement", 0o644)})
    assert archive.read_bytes() == b"public archive"


def test_unavailable_private_permissions_refuse_entire_batch_before_staging(
    release, tmp_path, monkeypatch,
):
    monkeypatch.delattr(release.os, "fchmod", raising=False)

    def no_staging(**kwargs):
        pytest.fail("private-output permission checks must precede staging")

    monkeypatch.setattr(release.tempfile, "mkstemp", no_staging)
    with pytest.raises(release.ReleaseError, match="private-output-permissions-unavailable"):
        release._write_new_files({
            tmp_path / "public": (b"public first", 0o644),
            tmp_path / "private": (b"synthetic private material", 0o600),
        })
    assert not list(tmp_path.iterdir())


def test_keygen_refuses_unavailable_private_permissions_without_partial_outputs(
    release, tmp_path, monkeypatch, capsys,
):
    monkeypatch.delattr(release.os, "fchmod", raising=False)
    assert release.main([
        "keygen", "--private-key", str(tmp_path / "private"),
        "--public-key", str(tmp_path / "public"),
    ]) != 0
    assert not list(tmp_path.iterdir())
    assert "private-output-permissions-unavailable" in capsys.readouterr().err


@pytest.mark.parametrize("replace_published", [False, True])
def test_without_fchmod_partial_failure_removes_only_owned_links(
    release, tmp_path, monkeypatch, replace_published,
):
    monkeypatch.delattr(release.os, "fchmod", raising=False)
    original_link = release.os.link
    first, second = tmp_path / "first", tmp_path / "second"
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"keep unrelated")

    def fail_second(source, destination, **kwargs):
        if destination == second:
            if replace_published:
                first.unlink()
                first.write_bytes(b"keep replacement")
            raise OSError("controlled publication failure")
        return original_link(source, destination, **kwargs)

    monkeypatch.setattr(release.os, "link", fail_second)
    with pytest.raises(OSError, match="controlled publication failure"):
        release._write_new_files({first: (b"first", 0o644), second: (b"second", 0o644)})
    expected = {"unrelated": b"keep unrelated"}
    if replace_published:
        expected["first"] = b"keep replacement"
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == expected


def test_without_fchmod_destination_race_never_overwrites_existing_file(
    release, tmp_path, monkeypatch,
):
    monkeypatch.delattr(release.os, "fchmod", raising=False)
    original_link = release.os.link
    destination = tmp_path / "archive"

    def competing_writer(source, target, **kwargs):
        target.write_bytes(b"other writer won")
        return original_link(source, target, **kwargs)

    monkeypatch.setattr(release.os, "link", competing_writer)
    with pytest.raises(FileExistsError):
        release._write_new_files({destination: (b"must not publish", 0o644)})
    assert list(tmp_path.iterdir()) == [destination]
    assert destination.read_bytes() == b"other writer won"
