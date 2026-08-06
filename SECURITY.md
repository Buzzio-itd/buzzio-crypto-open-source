# Security policy

## Scope

This repository contains a **sanitized educational copy** of messaging cryptography primitives. It does **not** include:

- Production account salts or challenge tokens
- Sealed-sender CA private keys
- Firebase / Cloud Functions delivery code
- The Buzzio application source

## Reporting issues

If you find a cryptographic design flaw in this reference code, please report it privately to the maintainers (do not open a public issue with a working exploit against live systems).

## Important

- Demo keys and example salts in tests/examples are **not** production secrets.
- This package is **not** wire-compatible with live Buzzio servers by design.
- Finding a bug here does not automatically mean the production app is exploitable in the same way; production code may differ.
