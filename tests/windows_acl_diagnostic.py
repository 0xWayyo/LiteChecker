"""Compare native and .NET ACL reads on disposable CI-owned objects only.

This is diagnostic evidence, not an ACL-policy bypass: inherited child owners
are left untouched and production acceptance/rejection is reported separately.
No paths, usernames, environment values or file contents are printed.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile

from litechecker import windows_security
from windows_test_support import secure_test_directory


DOTNET_READER = r"""
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$base=$env:LC_TEST_PRIVATE_ROOT
$paths=[ordered]@{
  parent=$base
  child_directory=[IO.Path]::Combine($base,'child')
  child_file=[IO.Path]::Combine($base,'child','fixture.txt')
  mode700_directory=[IO.Path]::Combine($base,'mode700')
  mode700_file=[IO.Path]::Combine($base,'mode700','fixture.txt')
}
$records=[ordered]@{}
foreach($label in $paths.Keys) {
  $path=$paths[$label]
  if($label.EndsWith('_file')) {$acl=[IO.File]::GetAccessControl($path)}
  else {$acl=[IO.Directory]::GetAccessControl($path)}
  $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
  $entries=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
    [ordered]@{kind=[int]$_.AccessControlType; mask=[uint32]$_.FileSystemRights; trustee=$_.IdentityReference.Value}
  })
  $records[$label]=[ordered]@{
    owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    current=$identity.User.Value
    present=($null -ne $raw.DiscretionaryAcl)
    entries=$entries
  }
}
[ordered]@{
  token=[ordered]@{
    current=$identity.User.Value
    default_owner=$identity.Owner.Value
    administrators_enabled=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  records=$records
} | ConvertTo-Json -Depth 6 -Compress
"""


def _native_record(path):
    owner, current, present, entries = windows_security._read_directory_acl(path)
    return {"owner": owner, "current": current, "present": present,
            "entries": [{"kind": kind, "mask": mask, "trustee": trustee}
                        for kind, mask, trustee in entries]}


def _comparable(record):
    return (record["owner"], record["current"], record["present"],
            sorted((entry["kind"], entry["mask"], entry["trustee"]) for entry in record["entries"]))


def main():
    if os.name != "nt":
        print("Windows ACL diagnostic requires native Windows")
        return 2
    with tempfile.TemporaryDirectory(prefix="litechecker-acl-diagnostic-") as temporary:
        parent = Path(temporary) / "private-parent"
        parent.mkdir()
        secure_test_directory(parent)
        child = parent / "child"
        child.mkdir()
        file = child / "fixture.txt"
        file.write_bytes(b"disposable diagnostic fixture")
        mode700 = parent / "mode700"
        mode700.mkdir(mode=0o700)
        mode700_file = mode700 / "fixture.txt"
        mode700_file.write_bytes(b"disposable diagnostic fixture")
        paths = {"parent": parent, "child_directory": child, "child_file": file,
                 "mode700_directory": mode700, "mode700_file": mode700_file}
        native = {label: _native_record(path) for label, path in paths.items()}
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", DOTNET_READER],
            env={**os.environ, "LC_TEST_PRIVATE_ROOT": str(parent)},
            capture_output=True, text=True, encoding="utf-8", timeout=20,
        )
        if result.returncode:
            print("Windows ACL diagnostic: independent .NET reader failed")
            return 1
        dotnet = json.loads(result.stdout)
        checks = {}
        for label, path in paths.items():
            check = windows_security.assert_private_file if label.endswith("_file") else windows_security.assert_private_directory
            try:
                check(path)
                checks[label] = "accepted"
            except (OSError, ValueError) as error:
                # Exception messages from these helpers are fixed, closed codes.
                checks[label] = str(error) if isinstance(error, ValueError) else "native-read-error"
        agreement = all(_comparable(native[label]) == _comparable(dotnet["records"][label]) for label in paths)
        print(json.dumps({"native": native, "dotnet": dotnet, "production_checks": checks,
                          "native_dotnet_agree": agreement}, sort_keys=True))
        return 0 if agreement else 1


if __name__ == "__main__":
    raise SystemExit(main())
