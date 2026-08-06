import 'dart:convert';
import 'dart:typed_data';

import 'crypto_engine.dart';

/// Sealed-sender helpers (reference).
///
/// Outer envelope: `ephemeralPub || AES-GCM(HKDF(ECDH(eph, recipientIK)))`
/// wrapping JSON `{ cert, msg }`.
///
/// Certificates are ECDSA-secp256k1 signed by a CA. Use a **demo CA** in tests;
/// never ship a real production CA private key in this package.
class SealedSender {
  SealedSender({CryptoEngine? crypto}) : _crypto = crypto ?? CryptoEngine();

  static const int version = 2;

  /// Generic label for this reference package (not live wire format).
  static const String hkdfInfo = 'sealed_sender_v1';
  static const String fromPlaceholder = 'sealed';
  static const Duration certTtl = Duration(hours: 24);

  final CryptoEngine _crypto;

  /// Seal [innerMessage] for [recipientIdentityPub] and attach [certificate].
  String seal({
    required Map<String, dynamic> certificate,
    required Map<String, dynamic> innerMessage,
    required Uint8List recipientIdentityPub,
  }) {
    final eph = _crypto.generateEphemeralKeyPair();
    final shared = _crypto.calculateSharedSecret(
      eph['private']!,
      recipientIdentityPub,
    );
    final sealedKey = _deriveSealedKey(shared);
    final payload = utf8.encode(jsonEncode({
      'v': version,
      'cert': certificate,
      'msg': innerMessage,
    }));
    final cipher = _crypto.encryptFast(Uint8List.fromList(payload), sealedKey);
    final ephPub = eph['public']!;
    final out = Uint8List(ephPub.length + cipher.length);
    out.setRange(0, ephPub.length, ephPub);
    out.setRange(ephPub.length, out.length, cipher);
    return _crypto.base64Encode(out);
  }

  /// Open a sealed envelope and verify the sender certificate with [caPublicKey].
  Map<String, dynamic>? open({
    required String envelopeBase64,
    required Uint8List recipientIdentityPriv,
    required Uint8List caPublicKey,
  }) {
    try {
      final raw = base64.decode(envelopeBase64);
      if (raw.length < 65 + 12) return null;
      final ephPub = Uint8List.fromList(raw.sublist(0, 65));
      if (ephPub[0] != 0x04) return null;
      final cipher = Uint8List.fromList(raw.sublist(65));
      final shared = _crypto.calculateSharedSecret(
        recipientIdentityPriv,
        ephPub,
      );
      final sealedKey = _deriveSealedKey(shared);
      final plain = _crypto.decryptFast(cipher, sealedKey);
      if (plain == null) return null;
      final decoded = jsonDecode(utf8.decode(plain));
      if (decoded is! Map) return null;
      final map = Map<String, dynamic>.from(decoded);
      final cert = map['cert'];
      final msg = map['msg'];
      if (cert is! Map || msg is! Map) return null;
      final certificate = Map<String, dynamic>.from(cert);
      final message = Map<String, dynamic>.from(msg);
      if (!verifySenderCertificate(certificate, caPublicKey: caPublicKey)) {
        return null;
      }
      if (!certificateBindsToMessage(certificate, message)) {
        return null;
      }
      return {
        'certificate': certificate,
        'message': message,
      };
    } catch (_) {
      return null;
    }
  }

  /// Issue a demo certificate (for tests/examples only).
  static Map<String, dynamic> issueDemoCertificate({
    required String ghostId,
    required Uint8List identityPublicKey,
    required Uint8List caPrivateKey,
    Duration ttl = certTtl,
    CryptoEngine? crypto,
  }) {
    final engine = crypto ?? CryptoEngine();
    final expMs = DateTime.now().add(ttl).millisecondsSinceEpoch;
    final ik = engine.base64Encode(identityPublicKey);
    final body = utf8.encode(jsonEncode({
      'v': 2,
      'gid': ghostId,
      'ik': ik,
      'exp': expMs,
    }));
    final sig = engine.signData(Uint8List.fromList(body), caPrivateKey);
    return {
      'v': 2,
      'gid': ghostId,
      'ik': ik,
      'exp': expMs,
      'sig': engine.base64Encode(sig),
    };
  }

  static bool verifySenderCertificate(
    Map<String, dynamic> certificate, {
    required Uint8List caPublicKey,
  }) {
    try {
      final v = certificate['v'];
      if (v != version && v != 2) return false;
      final gid = certificate['gid']?.toString();
      final ik = certificate['ik']?.toString();
      final exp = certificate['exp'];
      final sigB64 = certificate['sig']?.toString();
      if (gid == null || gid.isEmpty) return false;
      if (ik == null || ik.length < 40) return false;
      if (sigB64 == null || sigB64.isEmpty) return false;
      final expMs = exp is num ? exp.toInt() : int.tryParse('$exp');
      if (expMs == null || DateTime.now().millisecondsSinceEpoch > expMs) {
        return false;
      }
      final canonical = utf8.encode(jsonEncode({
        'v': 2,
        'gid': gid,
        'ik': ik,
        'exp': expMs,
      }));
      final sig = base64.decode(sigB64);
      if (sig.length != 64) return false;
      return CryptoEngine().verifySignature(
        Uint8List.fromList(canonical),
        Uint8List.fromList(sig),
        caPublicKey,
      );
    } catch (_) {
      return false;
    }
  }

  /// Structural binding: cert.gid == message.from; optional sender_pk ↔ ik.
  static bool certificateBindsToMessage(
    Map<String, dynamic> certificate,
    Map<String, dynamic> message,
  ) {
    final v = certificate['v'];
    if (v != version && v != 1 && v != 2) return false;
    final gid = certificate['gid']?.toString();
    final ik = certificate['ik']?.toString();
    final exp = certificate['exp'];
    final sig = certificate['sig']?.toString();
    if (gid == null || gid.isEmpty) return false;
    if (ik == null || ik.length < 40) return false;
    if (sig == null || sig.isEmpty) return false;
    final expMs = exp is num ? exp.toInt() : int.tryParse('$exp');
    if (expMs == null || DateTime.now().millisecondsSinceEpoch > expMs) {
      return false;
    }

    final from = message['from']?.toString();
    if (from == null || from.isEmpty || from == fromPlaceholder) return false;
    if (from != gid) return false;

    final senderPk = message['sender_pk']?.toString();
    if (senderPk != null && senderPk.isNotEmpty && senderPk != ik) {
      return false;
    }
    return true;
  }

  static bool isSealedEnvelope(Map<dynamic, dynamic> data) {
    final sealed = data['sealed'];
    if (sealed == 1 || sealed == true || sealed == '1') return true;
    final from = data['from']?.toString();
    return from == fromPlaceholder && data['envelope'] != null;
  }

  Uint8List _deriveSealedKey(Uint8List sharedSecret) {
    return _SealedHkdf.derive(sharedSecret, hkdfInfo);
  }
}

class _SealedHkdf {
  static Uint8List derive(Uint8List ikm, String info) {
    return CryptoEngine().derivePrivateKey(ikm, info);
  }
}
