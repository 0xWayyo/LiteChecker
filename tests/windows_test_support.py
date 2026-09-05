"""Native Windows fixtures; only explicitly supplied pytest directories change."""
import os
from pathlib import Path
import subprocess


def secure_test_directory(path: Path) -> Path:
    path = Path(path).absolute()
    if not path.is_dir() or path.is_symlink() or path == Path(path.anchor):
        raise ValueError("test directory must be an existing owned temporary directory")
    if os.name != "nt":
        path.chmod(0o700)
        return path
    script = r"""
$ErrorActionPreference='Stop'
$item=Get-Item -LiteralPath $env:LC_TEST_PRIVATE_ROOT -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse test directory' }
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
foreach($who in @($sid.Value,'S-1-5-18','S-1-5-32-544')) {
  $identity=[Security.Principal.SecurityIdentifier]::new($who)
  $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  [void]$acl.AddAccessRule($rule)
}
[IO.Directory]::SetAccessControl($env:LC_TEST_PRIVATE_ROOT,$acl)
"""
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        env={**os.environ, "LC_TEST_PRIVATE_ROOT": str(path)},
        capture_output=True, timeout=20,
    )
    if result.returncode:
        raise RuntimeError("controlled test directory ACL setup failed")
    return path
