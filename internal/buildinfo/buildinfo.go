package buildinfo

// Set by build.ps1, keeping CLI, tray and Windows file metadata consistent.
var Version = "v0.0.0-dev"
var Commit = "unknown"

func String() string { return "Torinator " + Version + " (" + Commit + ")" }
