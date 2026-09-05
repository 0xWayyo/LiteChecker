import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="native Windows bootstrap smoke")


@WINDOWS
@pytest.mark.parametrize("layout", ["wrapper", "flat"])
def test_batch_executes_controlled_powershell_with_canonical_root(tmp_path, layout):
    bundle = tmp_path / "LiteChecker"
    app = bundle / "_app" if layout == "wrapper" else bundle
    scripts = app / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(REPOSITORY / "LiteChecker.bat", bundle / "LiteChecker.bat")
    if layout == "flat":
        (app / "pyproject.toml").write_text("[project]\nname='fixture'\n")
        (app / "CONTENTS.sha256.json").write_text("{}\n")
    (scripts / "windows-native.ps1").write_text(
        "param([string]$Root,[string]$Action)\n"
        "$value = $Action + '|' + [IO.Path]::GetFullPath($Root)\n"
        "[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'dispatch.txt'), $value)\n",
        encoding="utf-8-sig",
    )
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", str(bundle / "LiteChecker.bat")],
        cwd=tmp_path, text=True, input="\n", capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    action, received = (scripts / "dispatch.txt").read_text().split("|", 1)
    assert action == "App"
    assert Path(received).resolve() == app.resolve()


@WINDOWS
def test_powershell_prepare_helpers_are_candidate_local_and_gate_bound(tmp_path):
    powershell = shutil.which("powershell.exe")
    assert powershell
    baseline = tmp_path / "LiteChecker" / "_app"
    baseline.mkdir(parents=True)
    harness = tmp_path / "native-smoke.ps1"
    harness.write_text(r"""
param([string]$ScriptPath,[string]$Baseline)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | ForEach-Object {$_.Message} | Out-String)}
foreach($fn in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){
  . ([scriptblock]::Create($fn.Extent.Text))
}
Protect-PrivateRoot $Baseline
Assert-PrivateRootAcl $Baseline
$candidate=Join-Path $Baseline '.updates\releases\0.5.1'
[void][IO.Directory]::CreateDirectory((Join-Path $candidate 'scripts'))
[IO.File]::WriteAllText((Join-Path $candidate 'scripts\windows-app-entry.py'),'# fixture')
Assert-NormalLayout $Baseline $candidate $false
$failed=$false
try { Assert-NormalLayout $Baseline (Join-Path ([IO.Directory]::GetParent($Baseline).FullName) '0.5.1') $false } catch { $failed=$true }
if(-not $failed){throw 'escaped release accepted'}
$state=Join-Path $Baseline 'windows-state'
[void][IO.Directory]::CreateDirectory($state)
$nonce='0123456789abcdef0123456789abcdef'
[IO.File]::WriteAllText((Join-Path $state "prepare-$nonce.gate"),$nonce,[Text.Encoding]::ASCII)
$script:RootPath=$Baseline
$script:ProjectPath=$candidate
$script:RuntimePath=Join-Path $candidate '.windows-native'
$script:AppEntryScript=Join-Path $candidate 'scripts\windows-app-entry.py'
$PrepareGate=$nonce
function Initialize-NativeRuntime([bool]$IncludeXray=$true) {
  [void][IO.Directory]::CreateDirectory($script:RuntimePath)
  [IO.File]::WriteAllText((Join-Path $script:RuntimePath 'prepared.fixture'),[string]$IncludeXray)
}
Invoke-PrepareRelease
if(-not [IO.File]::Exists((Join-Path $candidate '.windows-native\prepared.fixture'))){throw 'candidate not prepared'}
if([IO.Directory]::Exists((Join-Path $Baseline '.windows-native'))){throw 'baseline runtime changed'}
[IO.File]::WriteAllText((Join-Path $state "prepare-$nonce.gate"),'wrong',[Text.Encoding]::ASCII)
$failed=$false
try { Wait-PrepareGate $nonce } catch { $failed=$true }
if(-not $failed){throw 'wrong gate accepted'}
'ok'
""", encoding="utf-8-sig")
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ScriptPath", str(REPOSITORY / "scripts" / "windows-native.ps1"),
         "-Baseline", str(baseline)],
        text=True, capture_output=True, timeout=30,
        env={**os.environ, "PSModulePath": str(tmp_path / "intentionally-empty-modules")},
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert result.stdout.strip() == "ok"
    from litechecker.windows_security import assert_private_directory
    assert assert_private_directory(baseline) == baseline


@WINDOWS
@pytest.mark.parametrize("exit_code", [0, 7])
def test_powershell_app_streams_python_menu_and_preserves_exit_code(tmp_path, exit_code):
    powershell = shutil.which("powershell.exe")
    assert powershell
    root = tmp_path / ("success" if exit_code == 0 else "failure")
    root.mkdir()
    entry = tmp_path / "controlled-menu.py"
    entry.write_text(
        "import pathlib, sys\n"
        "root = pathlib.Path(sys.argv[sys.argv.index('--root') + 1])\n"
        "print('fixture-output', flush=True)\n"
        "value = input('fixture-input:')\n"
        "print('fixture-read:' + value, flush=True)\n"
        "raise SystemExit(0 if root.name == 'success' else 7)\n",
        encoding="utf-8",
    )
    harness = tmp_path / "app-smoke.ps1"
    harness.write_text(r"""
param([string]$ScriptPath,[string]$Python,[string]$Entry,[string]$Root)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | ForEach-Object {$_.Message} | Out-String)}
foreach($fn in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){
  . ([scriptblock]::Create($fn.Extent.Text))
}
function Assert-SafeRegularFile([string]$Path,[string]$Label) {}
function Protect-PrivateRoot([string]$Path) {}
function Initialize-NativeRuntime([bool]$IncludeXray=$true) {}
$script:PythonExe=$Python
$script:AppEntryScript=$Entry
$script:RootPath=$Root
Invoke-NormalApp
""", encoding="utf-8-sig")
    result = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
         "-ScriptPath", str(REPOSITORY / "scripts" / "windows-native.ps1"),
         "-Python", sys.executable, "-Entry", str(entry), "-Root", str(root)],
        text=True, input="controlled-input\n", capture_output=True, timeout=30,
    )
    assert "fixture-output" in result.stdout
    assert "fixture-input:" in result.stdout
    assert "fixture-read:controlled-input" in result.stdout
    assert (result.returncode == 0) is (exit_code == 0)
