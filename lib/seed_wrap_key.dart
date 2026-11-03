import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// 32-byte wrapping key derived from the identity master key with HKDF-SHA256
/// (16 zero-byte salt, caller-chosen info label).
///
/// Different labels give independent keys, so one master key can protect
/// several stores (for example a vault and a backup) without reuse.
///
/// The labels below are examples. A real deployment must pick its own.
class SeedWrapKey {
  SeedWrapKey._();

  static const exampleVaultInfo = 'example-vault-wrap-v1';
  static const exampleBackupInfo = 'example-backup-wrap-v1';
  static const int keyLength = 32;

  static Uint8List derive(Uint8List masterKey, String info) {
    if (masterKey.length != keyLength) {
      throw ArgumentError('Invalid master key length');
    }
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(masterKey, keyLength, Uint8List(16), utf8.encode(info)));
    return hkdf.process(Uint8List(0));
  }
}
