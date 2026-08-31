# Description

Gathering DebugSpace output (similar to DebugView) but with PowerShell.
For the cases where download of external tools is impossible.

# Running

1. Enable running PowerShell tools `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
2. Execute `.\PSDebugView.ps1`

# Testing

1. Run `.\PSDebugView.ps1`
2. Run `.\output_test.ps1`

