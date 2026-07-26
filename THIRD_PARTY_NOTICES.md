# Third-party notices

LinkForge's Go module dependencies include the WireGuard Go TUN implementation,
Wintun bindings, and Go `x/sys`/`x/net` modules. Their source and license texts
are available from:

- <https://git.zx2c4.com/wireguard-go/>
- <https://www.wintun.net/>
- <https://go.googlesource.com/sys/>
- <https://go.googlesource.com/net/>

The Wintun runtime DLL is not stored in this repository. Windows release
packagers must obtain the signed official DLL and comply with its distribution
terms. `go-licenses` or an equivalent SBOM/license scan should be part of a
public binary release process.
