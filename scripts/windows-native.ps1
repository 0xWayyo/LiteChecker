#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)]
    [string]$Root,
    [ValidateSet("Menu", "Diagnose", "App", "Prepare")]
    [string]$Action = "Menu",
    [string]$PrepareGate = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$systemModulePath = [System.IO.Path]::Combine($PSHOME, "Modules")
if (-not [System.IO.Directory]::Exists($systemModulePath)) {
    throw [System.InvalidOperationException]::new("Windows PowerShell system modules are unavailable.")
}
$env:PSModulePath = $systemModulePath

$UvVersion = "0.8.22"
$UvUrl = "https://github.com/astral-sh/uv/releases/download/0.8.22/uv-x86_64-pc-windows-msvc.zip"
$UvSha256 = "5049375aa2a5162f132b2c1cb992e25d42d47d934cab8c174dbe6f60973dcc12"
$XrayVersion = "26.3.27"
$XrayUrl = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-windows-64.zip"
$XraySha256 = "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad"
$PythonVersion = "3.12.11"
$AllowedAssetHosts = @("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com")
$DownloadTimeoutSeconds = 180
$MaximumRedirects = 5

function Fail([string]$Message) {
    throw [System.InvalidOperationException]::new($Message)
}

function Assert-NoReparsePoint([string]$Path, [string]$Label) {
    $current = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $current) {
        if (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "$Label не должен находиться в ссылке или reparse point."
        }
        if ($current -is [System.IO.FileInfo]) {
            $current = $current.Directory
        }
        else {
            $current = $current.Parent
        }
    }
}

function Ensure-LocalDirectory([string]$Path, [string]$Label) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if ([System.IO.Directory]::Exists($Path)) {
        Assert-NoReparsePoint $fullPath $Label
        return
    }
    if ([System.IO.File]::Exists($Path)) {
        Fail "$Label должен быть папкой."
    }
    $existingParent = [System.IO.Path]::GetDirectoryName($fullPath)
    while ($null -ne $existingParent -and -not [System.IO.Directory]::Exists($existingParent)) {
        $existingParent = [System.IO.Path]::GetDirectoryName($existingParent)
    }
    if ([string]::IsNullOrEmpty($existingParent)) {
        Fail "$Label не имеет безопасной существующей родительской папки."
    }
    Assert-NoReparsePoint $existingParent $Label
    [void][System.IO.Directory]::CreateDirectory($fullPath)
    Assert-NoReparsePoint $fullPath $Label
}

function Assert-SafeRegularFile([string]$Path, [string]$Label) {
    if (-not [System.IO.File]::Exists($Path)) {
        Fail "$Label не найден."
    }
    Assert-NoReparsePoint $Path $Label
}

function Assert-NativeHost {
    if ($env:WSL_DISTRO_NAME -or $env:WSL_INTEROP) {
        Fail "Эта проба запускается только нативно в Windows, не в WSL."
    }
    if (-not [Environment]::Is64BitOperatingSystem -or -not [Environment]::Is64BitProcess) {
        Fail "Нужна 64-битная Windows и 64-битный Windows PowerShell."
    }
    $architectures = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty Architecture -Unique)
    if ($architectures.Count -ne 1 -or [int]$architectures[0] -ne 9) {
        Fail "Поддерживается только Windows x64 на процессоре x86-64; ARM не поддерживается."
    }
}

function Get-NormalReleaseRoot {
    $release = (Get-Item -LiteralPath ([System.IO.Directory]::GetParent($PSScriptRoot).FullName) -Force).FullName
    Assert-NoReparsePoint $release "Папка выпуска"
    return $release
}

function Assert-NormalLayout([string]$Baseline, [string]$Release, [bool]$RequireBaseline) {
    if ([System.IO.Path]::GetFileName($Baseline) -cne "_app") {
        $manifest = [System.IO.Path]::Combine($Baseline, "CONTENTS.sha256.json")
        $project = [System.IO.Path]::Combine($Baseline, "pyproject.toml")
        if (-not [System.IO.File]::Exists($manifest) -or -not [System.IO.File]::Exists($project)) {
            Fail "Распакуйте LiteChecker в отдельную папку или используйте каталог _app."
        }
        Assert-SafeRegularFile $manifest "Манифест приложения"
        Assert-SafeRegularFile $project "Описание приложения"
    }
    if ($Release.Equals($Baseline, [StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    if ($RequireBaseline) {
        Fail "Меню можно запускать только из основной папки _app."
    }
    $version = [System.IO.Path]::GetFileName($Release)
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
        Fail "Папка выпуска имеет неверное имя версии."
    }
    $expectedParent = [System.IO.Path]::Combine($Baseline, ".updates", "releases")
    $actualParent = [System.IO.Directory]::GetParent($Release).FullName
    if (-not $actualParent.Equals($expectedParent, [StringComparison]::OrdinalIgnoreCase)) {
        Fail "Подготовка разрешена только для выпуска внутри _app\.updates\releases."
    }
}

function Get-PrivateAclIdentities {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    return @(
        $current,
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [System.Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    )
}

function Assert-PrivateRootAcl([string]$Path) {
    $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.IO.Directory]::GetAccessControl($Path)
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (-not $owner.Equals($current)) {
        Fail "Владелец папки _app не совпадает с текущим пользователем."
    }
    if (-not $acl.AreAccessRulesProtected) {
        Fail "Папка _app наследует посторонние права."
    }
    $allowed = @(Get-PrivateAclIdentities | ForEach-Object { $_.Value })
    foreach ($rule in @($acl.Access)) {
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $allowed -notcontains $sid -or
            ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl) {
            Fail "Права папки _app небезопасны."
        }
    }
    foreach ($sid in $allowed) {
        if (-not @($acl.Access | Where-Object {
            $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sid
        })) {
            Fail "В правах папки _app не хватает обязательной записи."
        }
    }
}

function Protect-PrivateRoot([string]$Path) {
    $identities = @(Get-PrivateAclIdentities)
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($identities[0])
    foreach ($identity in $identities) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    [System.IO.Directory]::SetAccessControl($Path, $security)
    Assert-PrivateRootAcl $Path
}

function Wait-PrepareGate([string]$Nonce) {
    if ([string]::IsNullOrEmpty($Nonce)) { return }
    if ($Nonce -notmatch '^[0-9a-fA-F]{32}$') {
        Fail "Неверный идентификатор prepare gate."
    }
    $state = [System.IO.Path]::Combine($script:RootPath, "windows-state")
    if (-not [System.IO.Directory]::Exists($state)) {
        Fail "Папка состояния для prepare gate не найдена."
    }
    Assert-NoReparsePoint $state "Папка состояния"
    $gate = [System.IO.Path]::Combine($state, "prepare-$Nonce.gate")
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ([System.IO.File]::Exists($gate)) {
            Assert-SafeRegularFile $gate "Prepare gate"
            $content = [System.IO.File]::ReadAllText($gate, [System.Text.Encoding]::ASCII)
            if ($content -cne $Nonce) {
                Fail "Prepare gate не подтверждён."
            }
            return
        }
        Start-Sleep -Milliseconds 100
    }
    Fail "Prepare gate не появился вовремя."
}

function Get-Sha256([string]$Path) {
    Assert-SafeRegularFile $Path "Файл для проверки SHA-256"
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-DownloadUri([Uri]$Uri) {
    if ($Uri.Scheme -cne "https" -or $AllowedAssetHosts -notcontains $Uri.DnsSafeHost.ToLowerInvariant()) {
        Fail "Download redirect left the pinned HTTPS GitHub asset hosts."
    }
    if (-not [string]::IsNullOrEmpty($Uri.UserInfo)) {
        Fail "Download URL credentials are not allowed."
    }
}

function Download-BoundedAsset([Uri]$Uri, [string]$Destination, [long]$MaximumBytes) {
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = $false
    $client = New-Object System.Net.Http.HttpClient($handler)
    $cancellation = New-Object System.Threading.CancellationTokenSource
    $cancellation.CancelAfter([TimeSpan]::FromSeconds($DownloadTimeoutSeconds))
    $response = $null
    $input = $null
    $output = $null
    try {
        $current = $Uri
        for ($redirect = 0; $redirect -le $MaximumRedirects; $redirect++) {
            Assert-DownloadUri $current
            if ($null -ne $response) {
                $response.Dispose()
                $response = $null
            }
            $response = $client.GetAsync(
                $current,
                [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead,
                $cancellation.Token
            ).GetAwaiter().GetResult()
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 303, 307, 308)) {
                if ($redirect -eq $MaximumRedirects -or $null -eq $response.Headers.Location) {
                    Fail "Download redirect limit exceeded."
                }
                $current = [Uri]::new($current, $response.Headers.Location)
                continue
            }
            if (-not $response.IsSuccessStatusCode) {
                Fail "Download failed with HTTP status $status."
            }
            $length = $response.Content.Headers.ContentLength
            if ($null -ne $length -and ([long]$length -lt 0 -or [long]$length -gt $MaximumBytes)) {
                Fail "Downloaded asset is larger than the configured limit."
            }
            $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            try {
                $output = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                $buffer = New-Object byte[] 65536
                [long]$total = 0
                while (($read = $input.ReadAsync($buffer, 0, $buffer.Length, $cancellation.Token).GetAwaiter().GetResult()) -gt 0) {
                    $total += $read
                    if ($total -gt $MaximumBytes) {
                        Fail "Downloaded asset is larger than the configured limit."
                    }
                    $output.Write($buffer, 0, $read)
                }
                $output.Flush($true)
                $output.Dispose()
                $output = $null
            }
            finally {
                if ($null -ne $input) {
                    $input.Dispose()
                    $input = $null
                }
            }
            return
        }
        Fail "Download redirect limit exceeded."
    }
    catch {
        if ($null -ne $output) {
            $output.Dispose()
        }
        if ([System.IO.File]::Exists($Destination)) {
            [System.IO.File]::Delete($Destination)
        }
        throw
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
        $cancellation.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Ensure-PinnedArchive(
    [string]$CachePath,
    [Uri]$Uri,
    [string]$ExpectedSha256,
    [long]$MaximumBytes,
    [string]$StagePath
) {
    if ([System.IO.File]::Exists($CachePath)) {
        Assert-SafeRegularFile $CachePath "Кэшированный архив"
        if ((Get-Sha256 $CachePath) -cne $ExpectedSha256) {
            Fail "Cached archive SHA-256 mismatch; remove only the altered archive and retry."
        }
        return
    }
    Download-BoundedAsset $Uri $StagePath $MaximumBytes
    if ((Get-Sha256 $StagePath) -cne $ExpectedSha256) {
        Fail "Downloaded archive SHA-256 mismatch."
    }
    [System.IO.File]::Move($StagePath, $CachePath)
}

function Open-ExactZipEntry([string]$ArchivePath, [string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [System.IO.File]::Open($ArchivePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        $matches = @($archive.Entries | Where-Object { $_.FullName -ceq $EntryName })
        if ($matches.Count -ne 1 -or $matches[0].Length -le 0 -or $matches[0].Length -gt 268435456) {
            $archive.Dispose()
            Fail "Pinned archive does not contain one bounded root executable."
        }
        return @($stream, $archive, $matches[0])
    }
    catch {
        $stream.Dispose()
        throw
    }
}

function Get-ZipEntrySha256([string]$ArchivePath, [string]$EntryName) {
    $opened = Open-ExactZipEntry $ArchivePath $EntryName
    $stream = $opened[0]
    $archive = $opened[1]
    $entry = $opened[2]
    $entryStream = $null
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $entryStream = $entry.Open()
        return ([System.BitConverter]::ToString($sha.ComputeHash($entryStream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        if ($null -ne $entryStream) { $entryStream.Dispose() }
        $sha.Dispose()
        $archive.Dispose()
        $stream.Dispose()
    }
}

function Extract-ExactZipEntry([string]$ArchivePath, [string]$EntryName, [string]$Destination) {
    $opened = Open-ExactZipEntry $ArchivePath $EntryName
    $stream = $opened[0]
    $archive = $opened[1]
    $entry = $opened[2]
    $entryStream = $null
    $output = $null
    try {
        $entryStream = $entry.Open()
        $output = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $entryStream.CopyTo($output)
        $output.Flush($true)
    }
    finally {
        if ($null -ne $output) { $output.Dispose() }
        if ($null -ne $entryStream) { $entryStream.Dispose() }
        $archive.Dispose()
        $stream.Dispose()
    }
}

function Ensure-ExecutableFromArchive(
    [string]$ArchivePath,
    [string]$EntryName,
    [string]$ExecutablePath,
    [string]$StagePath
) {
    $trustedEntrySha256 = Get-ZipEntrySha256 $ArchivePath $EntryName
    if ([System.IO.File]::Exists($ExecutablePath)) {
        Assert-SafeRegularFile $ExecutablePath "Кэшированный исполняемый файл"
        if ((Get-Sha256 $ExecutablePath) -cne $trustedEntrySha256) {
            Fail "Cached executable differs from its verified archive entry."
        }
        return
    }
    Extract-ExactZipEntry $ArchivePath $EntryName $StagePath
    if ((Get-Sha256 $StagePath) -cne $trustedEntrySha256) {
        Fail "Extracted executable verification failed."
    }
    [System.IO.File]::Move($StagePath, $ExecutablePath)
}

function Invoke-UvSync([string]$UvExe, [string]$RuntimePath) {
    $savedUv = @{}
    $processVariables = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
    foreach ($key in @($processVariables.Keys)) {
        $name = [string]$key
        if ($name.StartsWith("UV_", [StringComparison]::OrdinalIgnoreCase)) {
            $savedUv[$name] = [string]$processVariables[$key]
            [Environment]::SetEnvironmentVariable($name, $null, [EnvironmentVariableTarget]::Process)
        }
    }
    try {
        [Environment]::SetEnvironmentVariable("UV_PROJECT_ENVIRONMENT", [System.IO.Path]::Combine($RuntimePath, "venv"), "Process")
        [Environment]::SetEnvironmentVariable("UV_CACHE_DIR", [System.IO.Path]::Combine($RuntimePath, "cache", "uv"), "Process")
        [Environment]::SetEnvironmentVariable("UV_PYTHON_INSTALL_DIR", [System.IO.Path]::Combine($RuntimePath, "python"), "Process")
        [Environment]::SetEnvironmentVariable("UV_PYTHON_PREFERENCE", "only-managed", "Process")
        [Environment]::SetEnvironmentVariable("UV_PYTHON_INSTALL_BIN", "0", "Process")
        [Environment]::SetEnvironmentVariable("UV_PYTHON_INSTALL_REGISTRY", "0", "Process")
        Push-Location -LiteralPath $script:ProjectPath
        try {
            & $UvExe sync --no-install-project --no-build --frozen --no-dev --python $PythonVersion --no-config
            if ($LASTEXITCODE -ne 0) {
                Fail "uv sync failed with exit code $LASTEXITCODE."
            }
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $currentVariables = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
        foreach ($key in @($currentVariables.Keys)) {
            $name = [string]$key
            if ($name.StartsWith("UV_", [StringComparison]::OrdinalIgnoreCase)) {
                [Environment]::SetEnvironmentVariable($name, $null, [EnvironmentVariableTarget]::Process)
            }
        }
        foreach ($name in $savedUv.Keys) {
            [Environment]::SetEnvironmentVariable($name, $savedUv[$name], [EnvironmentVariableTarget]::Process)
        }
    }
}

function Initialize-NativeRuntime([bool]$IncludeXray = $true) {
    Ensure-LocalDirectory $script:RuntimePath "Локальный runtime"
    $downloads = [System.IO.Path]::Combine($script:RuntimePath, "downloads")
    $tools = [System.IO.Path]::Combine($script:RuntimePath, "tools")
    $uvDirectory = [System.IO.Path]::Combine($tools, "uv")
    $xrayDirectory = [System.IO.Path]::Combine($tools, "xray")
    $cacheDirectory = [System.IO.Path]::Combine($script:RuntimePath, "cache")
    $uvCacheDirectory = [System.IO.Path]::Combine($cacheDirectory, "uv")
    $pythonDirectory = [System.IO.Path]::Combine($script:RuntimePath, "python")
    $venvDirectory = [System.IO.Path]::Combine($script:RuntimePath, "venv")
    $runtimeDirectories = @($downloads, $tools, $uvDirectory, $cacheDirectory, $uvCacheDirectory, $pythonDirectory, $venvDirectory)
    if ($IncludeXray) {
        $runtimeDirectories += $xrayDirectory
    }
    foreach ($item in $runtimeDirectories) {
        Ensure-LocalDirectory $item "Локальный runtime"
    }
    $venvScriptsDirectory = [System.IO.Path]::Combine($venvDirectory, "Scripts")
    if ([System.IO.Directory]::Exists($venvScriptsDirectory) -or [System.IO.File]::Exists($venvScriptsDirectory)) {
        Ensure-LocalDirectory $venvScriptsDirectory "Локальный runtime"
    }
    $lockPath = [System.IO.Path]::Combine($script:RuntimePath, "bootstrap.lock")
    if ([System.IO.File]::Exists($lockPath)) {
        Assert-SafeRegularFile $lockPath "Bootstrap lock"
    }
    $lock = $null
    try {
        try {
            $lock = [System.IO.File]::Open($lockPath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        }
        catch [System.IO.IOException] {
            Fail "Другой процесс уже подготавливает локальные зависимости."
        }
        $stage = [System.IO.Path]::Combine($script:RuntimePath, "stage-" + [Guid]::NewGuid().ToString("N"))
        [void][System.IO.Directory]::CreateDirectory($stage)
        try {
            $uvArchive = [System.IO.Path]::Combine($downloads, "uv-$UvVersion.zip")
            Ensure-PinnedArchive $uvArchive ([Uri]$UvUrl) $UvSha256 67108864 ([System.IO.Path]::Combine($stage, "uv.zip"))
            Ensure-ExecutableFromArchive $uvArchive "uv.exe" $script:UvExe ([System.IO.Path]::Combine($stage, "uv.exe"))
            if ($IncludeXray) {
                $xrayArchive = [System.IO.Path]::Combine($downloads, "xray-$XrayVersion.zip")
                Ensure-PinnedArchive $xrayArchive ([Uri]$XrayUrl) $XraySha256 268435456 ([System.IO.Path]::Combine($stage, "xray.zip"))
                Ensure-ExecutableFromArchive $xrayArchive "xray.exe" $script:XrayExe ([System.IO.Path]::Combine($stage, "xray.exe"))
            }
            Invoke-UvSync $script:UvExe $script:RuntimePath
            Assert-SafeRegularFile $script:PythonExe "Локальный Python"
            if ($IncludeXray) {
                Assert-SafeRegularFile $script:XrayExe "Локальный Xray"
            }
        }
        finally {
            if ([System.IO.Directory]::Exists($stage)) {
                $stageItem = Get-Item -LiteralPath $stage -Force
                if (($stageItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
                    [System.IO.Directory]::Delete($stage, $true)
                }
            }
        }
    }
    finally {
        if ($null -ne $lock) { $lock.Dispose() }
    }
}

function Invoke-WindowsTrial([string[]]$Arguments) {
    Write-Host ""
    Write-Host "Подготовка может использовать текущее VPN. Измерение после подготовки использует привязанный путь."
    Initialize-NativeRuntime -IncludeXray $true
    Assert-SafeRegularFile $script:EntryScript "Локальный entry script"
    & $script:PythonExe -I -B $script:EntryScript --root $script:RootPath --xray $script:XrayExe @Arguments
    $result = $LASTEXITCODE
    if ($result -eq 130) { exit 130 }
    if ($result -ne 0) {
        Write-Host "Пробный запуск завершился с кодом $result. Это не подтверждает текущую доступность."
    }
}

function Invoke-WindowsDiagnostics {
    Write-Host ""
    Write-Host "Диагностика подготовит только uv, Python и зависимости. Xray, подписка и Telegram не используются."
    Initialize-NativeRuntime -IncludeXray $false
    Assert-SafeRegularFile $script:EntryScript "Локальный entry script"
    & $script:PythonExe -I -B $script:EntryScript --root $script:RootPath --diagnose
    $script:DiagnosticExitCode = $LASTEXITCODE
    if ($script:DiagnosticExitCode -eq 130) { exit 130 }
    if ($script:DiagnosticExitCode -ne 0) {
        Write-Host "Диагностика завершилась с кодом $script:DiagnosticExitCode."
    }
    else {
        Write-Host "Диагностика сохранена: $([System.IO.Path]::Combine($script:RootPath, 'windows-state', 'last-diagnostics.txt'))"
    }
}

function Invoke-CleanPython([string[]]$Arguments) {
    $savedPython = @{}
    $processVariables = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Process)
    foreach ($key in @($processVariables.Keys)) {
        $name = [string]$key
        if ($name.StartsWith("PYTHON", [StringComparison]::OrdinalIgnoreCase)) {
            $savedPython[$name] = [string]$processVariables[$key]
            [Environment]::SetEnvironmentVariable($name, $null, [EnvironmentVariableTarget]::Process)
        }
    }
    try {
        & $script:PythonExe -I -B $script:AppEntryScript @Arguments | Out-Host
        $script:AppExitCode = $LASTEXITCODE
    }
    finally {
        foreach ($name in $savedPython.Keys) {
            [Environment]::SetEnvironmentVariable($name, $savedPython[$name], [EnvironmentVariableTarget]::Process)
        }
    }
}

function Invoke-NormalApp {
    # This bootstrap/runtime stays stable. The isolated entry validates and
    # dispatches the active UI/runtime; its root argument remains the data root.
    Assert-SafeRegularFile $script:AppEntryScript "Локальный entry script"
    Protect-PrivateRoot $script:RootPath
    Initialize-NativeRuntime -IncludeXray $true
    $script:AppExitCode = 1
    Invoke-CleanPython @("menu", "--root", $script:RootPath)
    $result = $script:AppExitCode
    if ($result -ne 0) {
        Fail "LiteChecker завершился с кодом $result."
    }
}

function Invoke-PrepareRelease {
    Assert-PrivateRootAcl $script:RootPath
    Assert-SafeRegularFile $script:AppEntryScript "Локальный entry script"
    Wait-PrepareGate $PrepareGate
    Initialize-NativeRuntime -IncludeXray $true
}

function Show-LatestReport {
    $report = [System.IO.Path]::Combine($script:RootPath, "windows-state", "last-report.txt")
    if (-not [System.IO.File]::Exists($report)) {
        Write-Host "Последнего отчёта пока нет. Подготовка зависимостей не запускалась."
        return
    }
    Assert-SafeRegularFile $report "Последний отчёт"
    Write-Host ""
    Write-Host ([System.IO.File]::ReadAllText($report, [System.Text.Encoding]::UTF8))
}

function Pause-Menu {
    [void](Read-Host "Нажмите Enter, чтобы вернуться в меню")
}

try {
    Assert-NativeHost
    if (-not [string]::IsNullOrEmpty($PrepareGate) -and $Action -ne "Prepare") {
        Fail "Prepare gate разрешён только для действия Prepare."
    }
    $rootCandidate = [System.IO.Path]::GetFullPath($Root)
    if ($rootCandidate.StartsWith("\\", [StringComparison]::Ordinal)) {
        Fail "UNC и сетевые папки не поддерживаются. Распакуйте архив в локальную папку."
    }
    if (-not [System.IO.Directory]::Exists($rootCandidate)) {
        Fail "Корневая папка теста не найдена."
    }
    Assert-NoReparsePoint $rootCandidate "Корневая папка теста"
    $script:RootPath = (Get-Item -LiteralPath $rootCandidate -Force).FullName
    $script:ProjectPath = Get-NormalReleaseRoot
    Assert-NoReparsePoint $script:ProjectPath "Папка приложения"
    $normalAction = $Action -in @("App", "Prepare")
    if ($normalAction) {
        Assert-NormalLayout $script:RootPath $script:ProjectPath ($Action -eq "App")
        $script:RuntimePath = [System.IO.Path]::Combine($script:ProjectPath, ".windows-native")
    }
    else {
        $script:RuntimePath = [System.IO.Path]::Combine($script:RootPath, ".windows-native")
    }
    $script:EntryScript = [System.IO.Path]::Combine($script:ProjectPath, "scripts", "windows-entry.py")
    $script:AppEntryScript = [System.IO.Path]::Combine($script:ProjectPath, "scripts", "windows-app-entry.py")
    $script:UvExe = [System.IO.Path]::Combine($script:RuntimePath, "tools", "uv", "uv.exe")
    $script:XrayExe = [System.IO.Path]::Combine($script:RuntimePath, "tools", "xray", "xray.exe")
    $script:PythonExe = [System.IO.Path]::Combine($script:RuntimePath, "venv", "Scripts", "python.exe")

    if ($Action -eq "Prepare") {
        Invoke-PrepareRelease
        exit 0
    }
    if ($Action -eq "App") {
        Invoke-NormalApp
        exit 0
    }

    if ($Action -eq "Diagnose") {
        Invoke-WindowsDiagnostics
        exit $script:DiagnosticExitCode
    }

    while ($true) {
        Clear-Host
        Write-Host "LiteChecker Windows — ЭКСПЕРИМЕНТАЛЬНЫЙ РАЗОВЫЙ ТЕСТ"
        Write-Host "Автозапуска и фоновой службы нет. Ctrl+C останавливает текущий прогон."
        Write-Host ""
        Write-Host "1. Запустить один тест без Telegram"
        Write-Host "2. Показать последний отчёт"
        Write-Host "3. Настроить ссылку подписки"
        Write-Host "4. Настроить Telegram (необязательно)"
        Write-Host "5. Запустить новый тест и отправить отчёт в Telegram"
        Write-Host "6. Диагностика сети (при проблемах с TUN)"
        Write-Host "0. Выход"
        Write-Host ""
        $choice = Read-Host "Выберите действие"
        switch ($choice) {
            "1" { Invoke-WindowsTrial -Arguments @(); Pause-Menu }
            "2" { Show-LatestReport; Pause-Menu }
            "3" { Invoke-WindowsTrial -Arguments @("--setup"); Pause-Menu }
            "4" { Invoke-WindowsTrial -Arguments @("--configure-telegram"); Pause-Menu }
            "5" { Invoke-WindowsTrial -Arguments @("--send"); Pause-Menu }
            "6" { Invoke-WindowsDiagnostics; Pause-Menu }
            "0" { exit 0 }
            default { Write-Host "Неизвестный пункт меню."; Start-Sleep -Seconds 1 }
        }
    }
}
catch {
    Write-Host ""
    Write-Host "LiteChecker Windows остановлен: $($_.Exception.Message)"
    exit 2
}
