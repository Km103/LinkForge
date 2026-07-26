# Windows client

LinkForge uses WireGuard's Wintun backend. No TAP adapter is required. The
official architecture-specific `wintun.dll` must be beside `linkforge.exe`.
Obtain the signed package from <https://www.wintun.net/> and do not use DLLs
from mirrors.

## Build

From Linux:

```bash
make windows
```

Or from Windows with Go installed:

```powershell
go build -o linkforge.exe .\cmd\linkforge
.\linkforge.exe interfaces
.\linkforge.exe doctor -config profile.json -duration 10s
```

## One-click installation

The managed bundle contains the Windows executable, per-device profile,
installer, and official Wintun DLL. From an Administrator PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\deploy\windows\install-client-app.ps1 `
  -SourceBinary .\linkforge-windows-amd64.exe `
  -SourceProfile .\profile.json `
  -WintunDll .\wintun.dll
```

The installer:

- verifies that the Wintun DLL has a valid Authenticode signature;
- copies the binary/DLL under Program Files;
- copies the secret profile under ProgramData with a restricted ACL;
- registers a highest-privilege SYSTEM startup task for the local app;
- creates a LinkForge desktop URL shortcut.

Double-click **LinkForge**, then click **Aggregate traffic**. The client
discovers active physical default-route interfaces, calibrates their relative
weights, preserves one relay route per interface, and installs/removes tunnel
routes. No interface, route, gateway, or weight is entered by the user.

If the self-host profile uses `psk_env` instead of an inline managed key, set
that value as a protected machine environment variable before installation.
SYSTEM tasks cannot read a user-scoped variable.

## Advanced/manual operation

From an Administrator PowerShell:

```powershell
$env:LINKFORGE_CLIENT_KEY = "base64-key"
.\linkforge.exe client -config client.json
```

Use this path for explicit split routes and fixed path weights. Capture
`Get-NetRoute -AddressFamily IPv4` before manual route experiments. Stopping
the managed app waits for cleanup; if a manual process is force-killed, remove
only LinkForge routes/adapters after inspecting the routing table.

The legacy `install-client-task.ps1` registers already-installed files. New
installations should use `install-client-app.ps1`.
