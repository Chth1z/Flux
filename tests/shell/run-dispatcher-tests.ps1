$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$repoWsl = (& wsl.exe --cd $repo -- pwd).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoWsl)) {
    throw 'Could not translate the repository path for WSL.'
}

& wsl.exe -- bwrap `
    --tmpfs / `
    --ro-bind /usr /usr `
    --ro-bind /etc /etc `
    --symlink usr/bin /bin `
    --symlink usr/lib /lib `
    --symlink usr/lib64 /lib64 `
    --proc /proc `
    --dev /dev `
    --dir /tmp `
    --dir /data `
    --dir /data/adb `
    --dir /data/adb/modules `
    --dir /data/adb/magisk `
    --ro-bind $repoWsl /src `
    /usr/bin/sh /src/tests/shell/dispatcher_fluxd_mode.sh

exit $LASTEXITCODE
