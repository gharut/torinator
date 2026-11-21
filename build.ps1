param([string]$Archive)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if ((go env GOOS) -ne 'windows' -or (go env GOARCH) -ne 'amd64') {
        throw 'The current release target is windows/amd64.'
    }
    $version = '16.0.1'
    $name = "tor-expert-bundle-windows-x86_64-$version.tar.gz"
    $expected = '9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b'
    $asset = 'cmd/torinator/bundle.tar.gz'
    if ($Archive) {
        Copy-Item -LiteralPath $Archive -Destination $asset -Force
    } elseif (!(Test-Path $asset) -or (Get-FileHash $asset).Hash -ne $expected) {
        Invoke-WebRequest "https://dist.torproject.org/torbrowser/$version/$name" -OutFile $asset
    }
    if ((Get-FileHash $asset).Hash -ne $expected) { throw 'Tor archive checksum mismatch.' }
    go test ./...
    if ($LASTEXITCODE) { throw 'Tests failed.' }
    New-Item -ItemType Directory -Force dist | Out-Null
    go build -trimpath -o dist/torinator.exe ./cmd/torinator
    if ($LASTEXITCODE) { throw 'Build failed.' }
    & ./dist/torinator.exe -tor-version
    if ($LASTEXITCODE) { throw 'Embedded Tor startup failed.' }
} finally {
    Pop-Location
}
