import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart' hide Mac;

/// Group sender-key ratchet (Signal-style) with AES-GCM + ECDSA.
///
/// Pure Dart AES via [AesGcm] (no Flutter plugins) so this package runs on CLI.
class SenderKeyEngine {
  static final SenderKeyEngine _instance = SenderKeyEngine._internal();
  factory SenderKeyEngine() => _instance;
  SenderKeyEngine._internal();

  static final _aesGcm = AesGcm.with256bits();
  final ECDomainParameters _domain = ECDomainParameters('secp256k1');

  SenderKeyBundle generateSenderKey() {
    final chainKey = _randomBytes(32);
    final sigPriv = _randomBytes(32);
    final sigPub = _derivePublicKey(sigPriv);
    return SenderKeyBundle(
      chainKey: chainKey,
      signingPrivKey: sigPriv,
      signingPubKey: sigPub,
    );
  }

  Uint8List deriveMessageKey(Uint8List chainKey) =>
      _hmacSha256(chainKey, Uint8List.fromList([0x01]));

  Uint8List advanceChainKey(Uint8List chainKey) =>
      _hmacSha256(chainKey, Uint8List.fromList([0x02]));

  Future<SenderKeyMessage> encrypt({
    required String plaintext,
    required Uint8List chainKey,
    required int chainIndex,
    required Uint8List signingPrivKey,
  }) async {
    final messageKey = deriveMessageKey(chainKey);
    final secretKey = SecretKey(messageKey);
    final box = await _aesGcm.encrypt(
      Uint8List.fromList(utf8.encode(plaintext)),
      secretKey: secretKey,
    );

    final ciphertext = Uint8List.fromList([
      ...box.nonce,
      ...box.cipherText,
      ...box.mac.bytes,
    ]);
    final signature = _ecdsaSign(ciphertext, signingPrivKey);

    return SenderKeyMessage(
      chainIndex: chainIndex,
      ciphertext: ciphertext,
      signature: signature,
    );
  }

  Future<String?> decryptAsync({
    required SenderKeyMessage message,
    required Uint8List currentChainKey,
    required int currentChainIndex,
    required Uint8List signingPubKey,
    required Future<void> Function(Uint8List newChainKey, int newIndex)
        onChainAdvanced,
    required Future<Uint8List?> Function(int index) getSkippedKey,
    required Future<void> Function(int index, Uint8List key) saveSkippedKey,
  }) async {
    if (!_ecdsaVerify(message.ciphertext, message.signature, signingPubKey)) {
      return null;
    }

    late Uint8List messageKey;

    if (message.chainIndex < currentChainIndex) {
      final skipped = await getSkippedKey(message.chainIndex);
      if (skipped == null) return null;
      messageKey = skipped;
    } else {
      var chainKey = currentChainKey;
      var index = currentChainIndex;

      while (index < message.chainIndex) {
        final skipped = deriveMessageKey(chainKey);
        await saveSkippedKey(index, skipped);
        chainKey = advanceChainKey(chainKey);
        index++;
      }

      messageKey = deriveMessageKey(chainKey);
      final nextChainKey = advanceChainKey(chainKey);
      await onChainAdvanced(nextChainKey, index + 1);
    }

    return _aesGcmDecrypt(message.ciphertext, messageKey);
  }

  Future<String?> _aesGcmDecrypt(
      Uint8List ciphertext, Uint8List messageKey) async {
    try {
      if (ciphertext.length < 28) return null;
      final nonce = ciphertext.sublist(0, 12);
      final mac = Mac(ciphertext.sublist(ciphertext.length - 16));
      final ct = ciphertext.sublist(12, ciphertext.length - 16);
      final plainBytes = await _aesGcm.decrypt(
        SecretBox(ct, nonce: nonce, mac: mac),
        secretKey: SecretKey(messageKey),
      );
      return utf8.decode(plainBytes);
    } catch (_) {
      return null;
    }
  }

  Map<String, String> serializeDistribution({
    required String groupId,
    required String senderId,
    required Uint8List chainKey,
    required int chainIndex,
    required Uint8List signingPubKey,
  }) {
    return {
      'type': 'sender_key_distribution',
      'group_id': groupId,
      'sender_id': senderId,
      'chain_key': base64Encode(chainKey),
      'chain_index': chainIndex.toString(),
      'signing_pub_key': base64Encode(signingPubKey),
    };
  }

  SenderKeyDistribution? deserializeDistribution(Map<String, dynamic> data) {
    try {
      return SenderKeyDistribution(
        groupId: data['group_id'] as String,
        senderId: data['sender_id'] as String,
        chainKey: base64Decode(data['chain_key'] as String),
        chainIndex: int.parse(data['chain_index'].toString()),
        signingPubKey: base64Decode(data['signing_pub_key'] as String),
      );
    } catch (_) {
      return null;
    }
  }

  Uint8List _ecdsaSign(Uint8List data, Uint8List privateKeyBytes) {
    final privKeyNum = _bytesToBigInt(privateKeyBytes);
    final fortuna = FortunaRandom()..seed(KeyParameter(_randomBytes(32)));
    final signer = ECDSASigner(SHA256Digest())
      ..init(
          true,
          ParametersWithRandom(
            PrivateKeyParameter<ECPrivateKey>(ECPrivateKey(privKeyNum, _domain)),
            fortuna,
          ));
    final digest = SHA256Digest().process(data);
    final sig = signer.generateSignature(digest) as ECSignature;
    return Uint8List.fromList([
      ..._bigIntToBytes(sig.r, 32),
      ..._bigIntToBytes(sig.s, 32),
    ]);
  }

  bool _ecdsaVerify(
      Uint8List data, Uint8List signature, Uint8List pubKeyBytes) {
    try {
      if (signature.length != 64) return false;
      final r = _bytesToBigInt(signature.sublist(0, 32));
      final s = _bytesToBigInt(signature.sublist(32, 64));
      final pubPoint = _domain.curve.decodePoint(pubKeyBytes);
      if (pubPoint == null) return false;
      final verifier = ECDSASigner(SHA256Digest())
        ..init(
            false,
            PublicKeyParameter<ECPublicKey>(ECPublicKey(pubPoint, _domain)));
      final digest = SHA256Digest().process(data);
      return verifier.verifySignature(digest, ECSignature(r, s));
    } catch (_) {
      return false;
    }
  }

  Uint8List _hmacSha256(Uint8List key, Uint8List data) {
    final hmac = HMac(SHA256Digest(), 64)..init(KeyParameter(key));
    return hmac.process(data);
  }

  Uint8List _derivePublicKey(Uint8List privateKey) {
    final privNum = _bytesToBigInt(privateKey);
    final pubPoint = _domain.G * privNum;
    return pubPoint!.getEncoded(false);
  }

  /// Fail closed — never fall back to a weak PRNG.
  Uint8List _randomBytes(int length) {
    final rng = Random.secure();
    return Uint8List.fromList(List.generate(length, (_) => rng.nextInt(256)));
  }

  BigInt _bytesToBigInt(Uint8List bytes) => BigInt.parse(
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);

  Uint8List _bigIntToBytes(BigInt value, int length) {
    final hex = value.toRadixString(16).padLeft(length * 2, '0');
    return Uint8List.fromList(List.generate(
        length, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16)));
  }
}

class SenderKeyBundle {
  final Uint8List chainKey;
  final Uint8List signingPrivKey;
  final Uint8List signingPubKey;
  SenderKeyBundle({
    required this.chainKey,
    required this.signingPrivKey,
    required this.signingPubKey,
  });
}

class SenderKeyMessage {
  final int chainIndex;
  final Uint8List ciphertext;
  final Uint8List signature;

  SenderKeyMessage({
    required this.chainIndex,
    required this.ciphertext,
    required this.signature,
  });

  String toBase64() {
    final buf = BytesBuilder();
    buf.add((ByteData(4)..setUint32(0, chainIndex, Endian.big))
        .buffer
        .asUint8List());
    buf.add((ByteData(4)..setUint32(0, ciphertext.length, Endian.big))
        .buffer
        .asUint8List());
    buf.add(ciphertext);
    buf.add(signature);
    return base64Encode(buf.toBytes());
  }

  factory SenderKeyMessage.fromBase64(String b64) {
    final buf = base64Decode(b64);
    final chainIndex = ByteData.sublistView(buf, 0, 4).getUint32(0, Endian.big);
    final ctLen = ByteData.sublistView(buf, 4, 8).getUint32(0, Endian.big);
    final ciphertext = buf.sublist(8, 8 + ctLen);
    final signature = buf.sublist(8 + ctLen);
    return SenderKeyMessage(
      chainIndex: chainIndex,
      ciphertext: ciphertext,
      signature: signature,
    );
  }
}

class SenderKeyDistribution {
  final String groupId;
  final String senderId;
  final Uint8List chainKey;
  final int chainIndex;
  final Uint8List signingPubKey;
  SenderKeyDistribution({
    required this.groupId,
    required this.senderId,
    required this.chainKey,
    required this.chainIndex,
    required this.signingPubKey,
  });
}
