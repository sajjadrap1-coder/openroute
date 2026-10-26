# Local diagnostics for contributors (PowerShell, Go 1.23+).
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
go test ./...
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed.' }
go vet ./...
if ($LASTEXITCODE -ne 0) { throw 'Go vet failed.' }
go run ./cmd/openroute version
