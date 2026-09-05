# Legacy WSL entry; native Windows uses LiteChecker.bat.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

try {
    Write-Host 'LiteChecker — установка для Windows через Ubuntu / WSL 2'
    if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
        throw 'Сначала установите WSL 2 с Ubuntu: https://learn.microsoft.com/windows/wsl/install'
    }

    $installed = & wsl.exe --list --quiet
    if ($LASTEXITCODE -ne 0) {
        throw 'Не удалось запустить WSL. Установите WSL 2 с Ubuntu и один раз откройте Ubuntu: https://learn.microsoft.com/windows/wsl/install'
    }
    $distributions = @($installed | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ -match '^Ubuntu(?:-|$)' })
    if ($distributions.Count -eq 0) {
        throw 'Не найдена Ubuntu. Установите Ubuntu для WSL 2, откройте её и создайте пользователя: https://learn.microsoft.com/windows/wsl/install'
    }
    $distribution = $distributions[0]
    if ($distributions -contains 'Ubuntu') { $distribution = 'Ubuntu' }

    $details = & wsl.exe --list --verbose
    if ($LASTEXITCODE -ne 0) {
        throw 'Не удалось проверить версию WSL. Обновите WSL: https://learn.microsoft.com/windows/wsl/install'
    }
    $versionPattern = '^\s*\*?\s*' + [regex]::Escape($distribution) + '\s+.+?\s+2\s*$'
    $isWsl2 = @($details | ForEach-Object { $_ -replace "`0", '' } | Where-Object { $_ -match $versionPattern })
    if ($isWsl2.Count -eq 0) {
        throw "Для $distribution требуется WSL 2. Выполните в PowerShell: wsl --set-version $distribution 2. Затем снова откройте INSTALL.bat."
    }

    Write-Host "Использую $distribution. Docker Desktop должен быть запущен; включите для этой Ubuntu Settings → Resources → WSL Integration."
    $converted = & wsl.exe --distribution $distribution --exec wslpath -a -u $PSScriptRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Не удалось открыть папку в Ubuntu. Распакуйте ZIP на локальный диск и запустите INSTALL.bat снова.'
    }
    $linuxSource = ($converted -join "`n").Trim()
    if (-not $linuxSource.StartsWith('/')) {
        throw 'Не удалось определить путь к распакованной папке в Ubuntu.'
    }
    & wsl.exe --distribution $distribution --exec bash "$linuxSource/INSTALL.sh"
    exit $LASTEXITCODE
} catch {
    Write-Host ''
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host 'Docker Desktop: https://www.docker.com/products/docker-desktop/'
    Write-Host 'После подготовки Ubuntu и Docker снова откройте INSTALL.bat.'
    exit 2
}
