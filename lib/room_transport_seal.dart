import 'dart:convert';
import 'dart:typed_data';

import 'crypto_engine.dart';

/// AES-256-GCM envelope for a JSON payload under a shared room key (DEK).
///
/// Wire: `{ v, sealed: 1, kv, n: base64(nonce), ct: base64(ciphertext||tag) }`.
/// `kv` names the DEK generation so receivers pick the right key after
/// rotation. Opening never falls back to plaintext: a bad key or tampered
/// envelope returns null.
class RoomTransportSeal {
  RoomTransportSeal._();

  static const int version = 1;
  static final CryptoEngine _crypto = CryptoEngine();

  static bool isSealed(Map<dynamic, dynamic> data) {
    final sealed = data['sealed'];
    if (!(sealed == 1 || sealed == true || sealed == '1')) return false;
    final v = data['v'];
    if (v != null && v != version) return false;
    return data['n'] is String && data['ct'] is String;
  }

  static Map<String, dynamic> seal(
    Map<String, dynamic> payload,
    Uint8List dek, {
    int keyVersion = 1,
  }) {
    final plain = Uint8List.fromList(utf8.encode(jsonEncode(payload)));
    final encrypted = _crypto.encryptGCM(plain, dek);
    return {
      'v': version,
      'sealed': 1,
      'kv': keyVersion,
      'n': base64Encode(encrypted['nonce']!),
      'ct': base64Encode(encrypted['ciphertext']!),
    };
  }

  static Map<String, dynamic>? open(Map<dynamic, dynamic> envelope, Uint8List dek) {
    try {
      if (!isSealed(envelope)) return null;
      final nonce = base64Decode(envelope['n'].toString());
      final ciphertext = base64Decode(envelope['ct'].toString());
      final plain = _crypto.decryptGCM(ciphertext, dek, nonce);
      if (plain == null) return null;
      final decoded = jsonDecode(utf8.decode(plain));
      return decoded is Map ? Map<String, dynamic>.from(decoded) : null;
    } catch (_) {
      return null;
    }
  }
}
