import 'dart:typed_data';

import 'package:pointycastle/digests/sha512.dart';

/// Safety-number style fingerprint of two public keys (60 digits).
///
/// Both parties compute the same code: SHA-512 over the two keys in a fixed
/// order, first 30 bytes rendered as two decimal digits each, shown as twelve
/// groups of five. Compare in person or scan as a QR payload.
class SecurityCodeFingerprint {
  SecurityCodeFingerprint._(this.rawDigits, this.grouped);

  /// 60 decimal digits, no spaces (QR payload form).
  final String rawDigits;

  /// Twelve groups of five digits, space-separated.
  final String grouped;

  /// Normalises a scanned / pasted code to 60 digits, or null if malformed.
  static String? normalizeDigits(String? raw) {
    if (raw == null) return null;
    final digits = raw.replaceAll(RegExp(r'\D'), '');
    return digits.length == 60 ? digits : null;
  }

  /// True when [scanned] equals this fingerprint (spacing ignored).
  bool matchesScanned(String? scanned) {
    final n = normalizeDigits(scanned);
    return n != null && n == rawDigits;
  }

  /// Orders the keys lexicographically, so no account identifier is needed.
  static SecurityCodeFingerprint fromPublicKeys(Uint8List keyA, Uint8List keyB) {
    final aFirst = _compareBytes(keyA, keyB) <= 0;
    return _fromOrdered(aFirst ? keyA : keyB, aFirst ? keyB : keyA);
  }

  /// Orders the keys by their owners' sorted identifiers (1:1 chat style).
  static SecurityCodeFingerprint fromLabeledKeys({
    required String idA,
    required String idB,
    required Uint8List publicKeyA,
    required Uint8List publicKeyB,
  }) {
    final firstIsA = ([idA, idB]..sort()).first == idA;
    return _fromOrdered(
      firstIsA ? publicKeyA : publicKeyB,
      firstIsA ? publicKeyB : publicKeyA,
    );
  }

  static SecurityCodeFingerprint _fromOrdered(Uint8List first, Uint8List second) {
    final hash = SHA512Digest().process(Uint8List.fromList([...first, ...second]));
    final buffer = StringBuffer();
    for (var i = 0; i < 30; i++) {
      buffer.write(hash[i].toString().padLeft(2, '0'));
    }
    final digits = buffer.toString().substring(0, 60);
    final groups = [
      for (var i = 0; i < 60; i += 5) digits.substring(i, i + 5),
    ];
    return SecurityCodeFingerprint._(digits, groups.join(' '));
  }

  static int _compareBytes(Uint8List a, Uint8List b) {
    final n = a.length < b.length ? a.length : b.length;
    for (var i = 0; i < n; i++) {
      final d = a[i] - b[i];
      if (d != 0) return d;
    }
    return a.length - b.length;
  }
}
