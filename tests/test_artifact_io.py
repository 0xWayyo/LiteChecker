"""Author input safety is independent of any discontinued ZIP format."""
import os

import pytest

from test_platform_distribution import script


def read(path, root):
    return script("artifact_io").read_release_input(path, root=root)


def test_regular_nested_input_preserves_bytes(tmp_path):
    path = tmp_path / "src" / "nested.py"
    path.parent.mkdir()
    path.write_bytes(b"\x00\xff\nrelease input\r\n")
    assert read(path, tmp_path) == b"\x00\xff\nrelease input\r\n"


def test_input_outside_project_is_rejected(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    path = tmp_path / "private"
    path.write_bytes(b"outside")
    with pytest.raises(ValueError, match="inside the project"):
        read(path, root)


def test_dotdot_cannot_escape_project(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (tmp_path / "private").write_bytes(b"outside")
    with pytest.raises(ValueError, match="inside the project"):
        read(root / ".." / "private", root)


def test_symlink_project_root_is_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"must not ship")
    root = tmp_path / "project"
    root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="regular file"):
        read(root / "payload", root)


@pytest.mark.parametrize("linked_parent", [False, True])
def test_symlink_input_is_rejected(tmp_path, linked_parent):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"must not ship")
    if linked_parent:
        (root / "linked").symlink_to(outside, target_is_directory=True)
        path = root / "linked/payload"
    else:
        path = root / "payload"
        path.symlink_to(outside / "payload")
    with pytest.raises(ValueError, match="regular file"):
        read(path, root)


def test_directory_input_is_rejected(tmp_path):
    path = tmp_path / "directory"
    path.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        read(path, tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO")
def test_fifo_input_is_rejected_without_waiting_for_writer(tmp_path):
    path = tmp_path / "fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="regular file"):
        read(path, tmp_path)
