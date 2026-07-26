# Security policy

## Supported versions

LinkForge is currently an alpha and has not had an independent security audit.
Until a tagged stable release exists, only the latest commit receives fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Send a private report
to the repository security contact and include the affected commit, redacted
configuration, reproduction steps, expected impact, and whether exploitation
is suspected.

## Threat model

LinkForge aims to protect packet confidentiality and integrity from network
attackers between client and relay. It authenticates each authorized client,
rejects replayed datagrams, prevents assigned-IP spoofing, and accepts NAT
rebinding only after AEAD authentication.

It does not protect traffic after the relay, a compromised endpoint/kernel,
traffic analysis, denial of service, unauthenticated public dashboard access,
or DNS/route leaks caused by configuration.

## Key handling

Use one random key per client. Prefer `psk_env`; protect the service environment
and config with OS ACLs. Never commit keys. Rotate a key after suspected
disclosure and restart both endpoints.

## Cryptography

The implementation uses AES-256-GCM, HMAC-SHA256, HKDF-SHA256, random
nonces/IDs, direction-separated GCM nonces, and authenticated headers. These
are established primitives, but their composition needs an independent audit
before high-risk use.
