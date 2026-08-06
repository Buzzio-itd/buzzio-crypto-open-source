# Buzzio Crypto (reference)

Educational Dart package that shows how a Signal-protocol-class messaging stack can be built: **secp256k1** identity keys, **X3DH**, **Double Ratchet**, **AES-GCM**, **sealed-sender envelopes**, and **group sender keys**.

This is **not** the Buzzio mobile app. The production app, Firebase delivery, Cloud Functions, and account salts remain closed source.

## What this package is for

- Developers who want to understand the crypto *layer* (algorithms and key flow)
- Local experiments and unit tests with **generated** keys

## What is intentionally omitted

| Omitted | Why |
|---------|-----|
| Production PBKDF2 salts / HKDF peppers | Offline mnemonic attacks |
| Identity / Firestore key lookup | App infrastructure |
| Sealed delivery Cloud Functions | Live abuse / routing surface |
| Real CA private key | Would break trust for all clients |
| Firebase RTDB paths / callable names | Reconnaissance against production |

Security of messaging crypto must not depend on hiding the algorithms ([Kerckhoffs's principle](https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle)). Security *does* depend on keeping private keys, CA material, and production peppers secret.

## Stack (conceptual)

```
12-word mnemonic
  └── PBKDF2 + HKDF → identity keypair (secp256k1)
        ├── X3DH → shared secret
        ├── Double Ratchet → per-message AES-GCM keys
        ├── Sealed envelope (ephemeral ECDH → HKDF → AES-GCM)
        └── Sender keys (groups): HMAC chain + AES-GCM + ECDSA
```

HKDF info strings in **this** package use generic labels (for example `sealed_sender_v1`). They are **not** guaranteed to match live Buzzio wire format.

## Quick start

```bash
cd open-source/buzzio-crypto
dart pub get
dart test
dart run example/demo.dart
```

## License

This project is licensed under the **GNU General Public License v2.0** (same family as [Telegram’s open-source clients](https://github.com/DrKLO/Telegram)). See [LICENSE](LICENSE).

```
Copyright (C) 2026 Buzzio contributors
```

## Disclaimer

Provided for education and review. Do not treat this package as a drop-in replacement for production Buzzio, and do not reuse demo salts or demo CA keys in a real product.

The Buzzio **application** (servers, Firebase wiring, production salts, CA keys) is **not** open source — only this educational crypto reference package is.
