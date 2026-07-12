$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
& wsl.exe --cd $repo -- env FLUX_DISPATCHER_TESTS_REQUIRED=1 `
    sh tests/shell/run-dispatcher-tests.sh

exit $LASTEXITCODE
