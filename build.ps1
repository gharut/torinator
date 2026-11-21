param(
    [string]$Archive, [string]$SingBoxArchive, [string]$WintunArchive,
    [ValidatePattern('^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-dev)?$')]
    [string]$Version = 'v0.0.0-dev',
    [ValidatePattern('^(unknown|[a-fA-F0-9]{7,40})$')]
    [string]$Commit = 'unknown'
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if ((go env GOOS) -ne 'windows' -or (go env GOARCH) -ne 'amd64') {
        throw 'The current release target is windows/amd64.'
    }
    if ($Commit -eq 'unknown') {
        $revision = git rev-parse HEAD
        if ($LASTEXITCODE -eq 0) { $Commit = $revision.Trim() }
    }
    go run ./tools/resourcegen -version $Version
    if ($LASTEXITCODE) { throw 'Windows resource generation failed.' }
    New-Item -ItemType Directory -Force internal/assets | Out-Null
    $runtimes = @(
        @{
            Path = 'internal/assets/tor.tar.gz'; Local = $Archive
            URL = 'https://dist.torproject.org/torbrowser/16.0.1/tor-expert-bundle-windows-x86_64-16.0.1.tar.gz'
            SHA256 = '9eed3c3ff1fe43df034ce360196c9ec95472560d77ff55614d0cd5120edea27b'
        },
        @{
            Path = 'internal/assets/sing-box.zip'; Local = $SingBoxArchive
            URL = 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip'
            SHA256 = '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
        },
        @{
            Path = 'internal/assets/wintun.zip'; Local = $WintunArchive
            URL = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
            SHA256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
        }
    )
    foreach ($runtime in $runtimes) {
        if ($runtime.Local) {
            if ([IO.Path]::GetFullPath($runtime.Local) -ne [IO.Path]::GetFullPath($runtime.Path)) {
                Copy-Item -LiteralPath $runtime.Local -Destination $runtime.Path -Force
            }
        } elseif (!(Test-Path -LiteralPath $runtime.Path) -or (Get-FileHash -LiteralPath $runtime.Path).Hash -ne $runtime.SHA256) {
            Invoke-WebRequest $runtime.URL -OutFile $runtime.Path
        }
        if ((Get-FileHash -LiteralPath $runtime.Path).Hash -ne $runtime.SHA256) { throw "Checksum mismatch: $($runtime.Path)" }
    }
    go test ./...
    if ($LASTEXITCODE) { throw 'Tests failed.' }
    go vet ./...
    if ($LASTEXITCODE) { throw 'Go vet failed.' }
    New-Item -ItemType Directory -Force dist | Out-Null
    # Check the actual embedded payloads before linking the windowless release.
    $linkFlags = "-X github.com/gharut/torinator/internal/buildinfo.Version=$Version -X github.com/gharut/torinator/internal/buildinfo.Commit=$Commit"
    go build -trimpath -ldflags $linkFlags -o dist/torinator-check.exe ./cmd/torinator
    if ($LASTEXITCODE) { throw 'Build failed.' }
    & ./dist/torinator-check.exe -self-test
    if ($LASTEXITCODE) { throw 'Embedded runtime check failed.' }
    go build -trimpath -ldflags "-H=windowsgui -s -w $linkFlags" -o dist/torinator.exe ./cmd/torinator
    if ($LASTEXITCODE) { throw 'Release build failed.' }
    Remove-Item -LiteralPath dist/torinator-check.exe
    Copy-Item -LiteralPath internal/assets/THIRD_PARTY_NOTICES.md -Destination dist/THIRD_PARTY_NOTICES.md -Force
    Copy-Item -LiteralPath README.md -Destination dist/README.md -Force
    @{ version = $Version; commit = $Commit; platform = 'windows/amd64' } |
        ConvertTo-Json | Set-Content -LiteralPath dist/build-info.json -Encoding utf8
    $fileInfo = (Get-Item -LiteralPath dist/torinator.exe).VersionInfo
    if ($fileInfo.ProductVersion -ne $Version -or $fileInfo.ProductName -ne 'Torinator') {
        throw 'Executable version resources do not match the build version.'
    }
    Get-FileHash -LiteralPath dist/torinator.exe
} finally {
    Pop-Location
}
