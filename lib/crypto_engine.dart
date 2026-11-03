import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:bip39/bip39.dart' as bip39;
import 'package:pointycastle/export.dart';

/// Reference E2EE engine: BIP39 → PBKDF2 → HKDF identity keys, ECDH/X3DH,
/// Double Ratchet, AES-GCM, ECDSA on secp256k1.
///
/// Example [defaultSalt] / [defaultHkdfLabel] below are **not** production values.
class CryptoEngine {
  CryptoEngine({
    this.pbkdf2Iterations = defaultPbkdf2Iterations,
  });

  /// Demo-only defaults — replace in any real deployment.
  static const int defaultPbkdf2Iterations = 100000;
  static const String defaultSalt = 'EXAMPLE_SALT_CHANGE_ME';
  static const String defaultHkdfLabel = 'EXAMPLE_E2EE_KEY';

  final int pbkdf2Iterations;
  final ECDomainParameters _domainParams = ECDomainParameters('secp256k1');

  static Future<Map<String, Uint8List>> deriveKeysIsolate({
    required String mnemonic,
    required String salt,
    required String hkdfLabel,
    int pbkdf2Iterations = defaultPbkdf2Iterations,
  }) async {
    return Isolate.run(() {
      final engine = CryptoEngine(pbkdf2Iterations: pbkdf2Iterations);
      final seed = engine.deriveRootSeed(mnemonic);
      final masterKey = engine.deriveMasterKey(seed, salt);
      final privateKey = engine.derivePrivateKey(masterKey, hkdfLabel);
      final publicKey = engine.derivePublicKey(privateKey);
      return {
        'masterKey': masterKey,
        'privateKey': privateKey,
        'publicKey': publicKey,
      };
    });
  }

  static Future<Uint8List> encryptMessageIsolate({
    required String plaintext,
    required Uint8List myPrivateKey,
    required Uint8List theirPublicKey,
    required String conversationId,
  }) async {
    return Isolate.run(() => CryptoEngine().encryptMessage(
          plaintext,
          myPrivateKey,
          theirPublicKey,
          conversationId,
        ));
  }

  static Future<String?> decryptMessageIsolate({
    required Uint8List encryptedBlob,
    required Uint8List myPrivateKey,
    required Uint8List theirPublicKey,
    required String conversationId,
  }) async {
    return Isolate.run(() => CryptoEngine().decryptMessage(
          encryptedBlob,
          myPrivateKey,
          theirPublicKey,
          conversationId,
        ));
  }

  static Future<Uint8List> encryptBytesIsolate({
    required Uint8List data,
    required Uint8List myPrivateKey,
    required Uint8List theirPublicKey,
    required String contextId,
  }) async {
    return Isolate.run(() => CryptoEngine().encryptBytesForRecipient(
          data,
          myPrivateKey,
          theirPublicKey,
          contextId,
        ));
  }

  static Future<Uint8List?> decryptBytesIsolate({
    required Uint8List encryptedBlob,
    required Uint8List myPrivateKey,
    required Uint8List theirPublicKey,
    required String contextId,
  }) async {
    return Isolate.run(() => CryptoEngine().decryptBytesFromSender(
          encryptedBlob,
          myPrivateKey,
          theirPublicKey,
          contextId,
        ));
  }

  static Future<Uint8List> deriveMessageKeyIsolate({
    required Uint8List myPrivateKey,
    required Uint8List theirPublicKey,
    required String conversationId,
  }) async {
    return Isolate.run(() {
      final engine = CryptoEngine();
      final sharedSecret =
          engine.calculateSharedSecret(myPrivateKey, theirPublicKey);
      return engine.deriveConversationKey(sharedSecret, conversationId);
    });
  }

  static Future<Map<String, Uint8List>> initializeRatchetIsolate({
    required Uint8List sharedSecret,
    required String conversationId,
  }) async {
    return Isolate.run(
        () => CryptoEngine().initializeRatchet(sharedSecret, conversationId));
  }

  static Future<Map<String, Uint8List>> ratchetChainKeyIsolate(
      Uint8List chainKey) async {
    return Isolate.run(() => CryptoEngine().ratchetChainKey(chainKey));
  }

  /// Legacy bootstrap: split 64-byte X3DH material into root + chain.
  /// Prefer [extractX3dhSharedKey] + [ratchetInitAlice] for v2 sessions.
  Map<String, Uint8List> initializeRatchet(
      Uint8List sharedSecret, String conversationId) {
    Uint8List material = sharedSecret;
    if (material.length < 64) {
      final hkdf = HKDFKeyDerivator(SHA256Digest())
        ..init(HkdfParameters(material, 64, utf8.encode(conversationId)));
      material = hkdf.process(Uint8List(0));
    }
    return {
      'rootKey': material.sublist(0, 32),
      'chainKey': material.sublist(32, 64),
    };
  }

  Uint8List extractX3dhSharedKey(Uint8List x3dhMaterial) {
    if (x3dhMaterial.length >= 32) {
      return Uint8List.fromList(x3dhMaterial.sublist(0, 32));
    }
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(x3dhMaterial, 32, utf8.encode('X3DH')));
    return hkdf.process(Uint8List(0));
  }

  /// RatchetInitAlice — sender after X3DH.
  Map<String, dynamic> ratchetInitAlice({
    required Uint8List sharedKey,
    required Uint8List bobSignedPreKeyPub,
  }) {
    final dhs = generateEphemeralKeyPair();
    final rkCk = dhRatchetStep(
      rootKey: sharedKey,
      ourRatchetPriv: dhs['private']!,
      theirRatchetPub: bobSignedPreKeyPub,
    );
    return {
      'rootKey': rkCk['rootKey']!,
      'sendingChainKey': rkCk['chainKey']!,
      'dhRatchetPriv': dhs['private']!,
      'dhRatchetPub': dhs['public']!,
      'theirDhRatchetPub': bobSignedPreKeyPub,
    };
  }

  /// RatchetInitBob — receiver after X3DH.
  Map<String, dynamic> ratchetInitBob({
    required Uint8List sharedKey,
    required Uint8List bobSignedPreKeyPriv,
    required Uint8List bobSignedPreKeyPub,
  }) {
    return {
      'rootKey': sharedKey,
      'dhRatchetPriv': bobSignedPreKeyPriv,
      'dhRatchetPub': bobSignedPreKeyPub,
    };
  }

  /// Inbound DH ratchet step only (existing local DH priv × peer's new pub).
  ///
  /// Must mirror the peer's [dhRatchetSendStep]. Chaining a send-step here
  /// desynchronises the root chain and every later message fails to decrypt.
  Map<String, Uint8List> dhRatchetReceiveStep({
    required Uint8List rootKey,
    required Uint8List ourRatchetPriv,
    required Uint8List theirRatchetPub,
  }) =>
      dhRatchetStep(
        rootKey: rootKey,
        ourRatchetPriv: ourRatchetPriv,
        theirRatchetPub: theirRatchetPub,
      );

  /// Outbound first reply — new local DH × peer's stored pub.
  Map<String, dynamic> dhRatchetSendStep({
    required Uint8List rootKey,
    required Uint8List theirRatchetPub,
    required int previousSendingIndex,
  }) {
    final newDh = generateEphemeralKeyPair();
    final sendStep = dhRatchetStep(
      rootKey: rootKey,
      ourRatchetPriv: newDh['private']!,
      theirRatchetPub: theirRatchetPub,
    );
    return {
      'rootKey': sendStep['rootKey']!,
      'chainKey': sendStep['chainKey']!,
      'dhRatchetPriv': newDh['private']!,
      'dhRatchetPub': newDh['public']!,
      'chainPn': previousSendingIndex,
    };
  }

  /// Bootstrap / tests only — recv + send in one call.
  Map<String, dynamic> dhRatchetFullStep({
    required Uint8List rootKey,
    required Uint8List ourRatchetPriv,
    required Uint8List theirRatchetPub,
    required int previousSendingIndex,
  }) {
    final recvStep = dhRatchetStep(
      rootKey: rootKey,
      ourRatchetPriv: ourRatchetPriv,
      theirRatchetPub: theirRatchetPub,
    );
    final newDh = generateEphemeralKeyPair();
    final sendStep = dhRatchetStep(
      rootKey: recvStep['rootKey']!,
      ourRatchetPriv: newDh['private']!,
      theirRatchetPub: theirRatchetPub,
    );
    return {
      'rootKey': sendStep['rootKey']!,
      'receivingChainKey': recvStep['chainKey']!,
      'sendingChainKey': sendStep['chainKey']!,
      'dhRatchetPriv': newDh['private']!,
      'dhRatchetPub': newDh['public']!,
      'chainPn': previousSendingIndex,
    };
  }

  /// DH ratchet: HKDF(salt=rootKey, ikm=ECDH, info='WhisperRatchet') → 64 bytes.
  Map<String, Uint8List> dhRatchetStep({
    required Uint8List rootKey,
    required Uint8List ourRatchetPriv,
    required Uint8List theirRatchetPub,
  }) {
    final dh = calculateSharedSecret(ourRatchetPriv, theirRatchetPub);
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(dh, 64, utf8.encode('WhisperRatchet'), rootKey));
    final output = hkdf.process(Uint8List(0));
    return {
      'rootKey': output.sublist(0, 32),
      'chainKey': output.sublist(32, 64),
    };
  }

  /// ECDSA-SHA256; returns 64-byte r || s.
  Uint8List signData(Uint8List data, Uint8List privateKey) {
    final privKeyNum = BigInt.parse(hexEncode(privateKey), radix: 16);
    final privKey = ECPrivateKey(privKeyNum, _domainParams);
    final fortuna = FortunaRandom();
    fortuna.seed(KeyParameter(_generateRandom32Bytes()));
    final signer = ECDSASigner(SHA256Digest())
      ..init(
          true,
          ParametersWithRandom(
              PrivateKeyParameter<ECPrivateKey>(privKey), fortuna));
    final digest = SHA256Digest().process(data);
    final sig = signer.generateSignature(digest) as ECSignature;
    final result = Uint8List(64);
    final rBytes = _bigIntToUint8List(sig.r);
    final sBytes = _bigIntToUint8List(sig.s);
    result.setRange(32 - rBytes.length, 32, rBytes);
    result.setRange(64 - sBytes.length, 64, sBytes);
    return result;
  }

  bool verifySignature(
      Uint8List data, Uint8List signature, Uint8List publicKey) {
    try {
      if (signature.length != 64) return false;
      final r = BigInt.parse(hexEncode(signature.sublist(0, 32)), radix: 16);
      final s = BigInt.parse(hexEncode(signature.sublist(32, 64)), radix: 16);
      final pubPoint = _domainParams.curve.decodePoint(publicKey);
      final pubKey = ECPublicKey(pubPoint, _domainParams);
      final verifier = ECDSASigner(SHA256Digest())
        ..init(false, PublicKeyParameter<ECPublicKey>(pubKey));
      final digest = SHA256Digest().process(data);
      return verifier.verifySignature(digest, ECSignature(r, s));
    } catch (_) {
      return false;
    }
  }

  Map<String, Uint8List> ratchetChainKey(Uint8List chainKey) {
    final hmacMessage = HMac(SHA256Digest(), 64)..init(KeyParameter(chainKey));
    final messageKey = hmacMessage.process(Uint8List.fromList([0x01]));
    final hmacChain = HMac(SHA256Digest(), 64)..init(KeyParameter(chainKey));
    final nextChainKey = hmacChain.process(Uint8List.fromList([0x02]));
    return {
      'messageKey': messageKey,
      'nextChainKey': nextChainKey,
    };
  }

  /// AES-GCM with optional associated data; returns nonce(12) || ct || tag(16).
  Uint8List encryptFast(
    Uint8List plaintext,
    Uint8List messageKey, {
    Uint8List? aad,
  }) {
    final encryptedMap = encryptGCM(plaintext, messageKey, aad: aad);
    final nonce = encryptedMap['nonce']!;
    final ciphertext = encryptedMap['ciphertext']!;
    final result = Uint8List(nonce.length + ciphertext.length);
    result.setRange(0, nonce.length, nonce);
    result.setRange(nonce.length, result.length, ciphertext);
    return result;
  }

  /// Inverse of [encryptFast]. [aad] must match the sender's exactly.
  Uint8List? decryptFast(
    Uint8List encryptedBlob,
    Uint8List messageKey, {
    Uint8List? aad,
  }) {
    if (encryptedBlob.length < 12) return null;
    final nonce = encryptedBlob.sublist(0, 12);
    final ciphertext = encryptedBlob.sublist(12);
    return decryptGCM(ciphertext, messageKey, nonce, aad: aad);
  }

  Map<String, Uint8List> generatePreKeyBundle(int count) {
    final Map<String, Uint8List> bundle = {};
    final signedPriv = _generateRandom32Bytes();
    final signedPub = derivePublicKey(signedPriv);
    bundle['signed_key'] = signedPriv;
    bundle['signed_key_pub'] = signedPub;
    for (var i = 0; i < count; i++) {
      final privateKey = _generateRandom32Bytes();
      final publicKey = derivePublicKey(privateKey);
      final keyId = 'pk_${DateTime.now().microsecondsSinceEpoch}_$i';
      bundle[keyId] = privateKey;
      bundle['${keyId}_pub'] = publicKey;
    }
    return bundle;
  }

  Uint8List _generateRandom32Bytes() {
    final bytes = Uint8List(32);
    final random = Random.secure();
    for (var j = 0; j < 32; j++) {
      bytes[j] = random.nextInt(256);
    }
    return bytes;
  }

  /// X3DH sender: DH1..DH4 then HKDF → 64 bytes.
  Uint8List calculateX3DHSecret({
    required Uint8List myIdentityPrivateKey,
    required Uint8List myEphemeralPrivateKey,
    required Uint8List theirIdentityPublicKey,
    required Uint8List theirSignedPreKey,
    Uint8List? theirOneTimePreKey,
  }) {
    final dh1 = calculateSharedSecret(myIdentityPrivateKey, theirSignedPreKey);
    final dh2 =
        calculateSharedSecret(myEphemeralPrivateKey, theirIdentityPublicKey);
    final dh3 = calculateSharedSecret(myEphemeralPrivateKey, theirSignedPreKey);

    late Uint8List ikm;
    if (theirOneTimePreKey != null) {
      final dh4 =
          calculateSharedSecret(myEphemeralPrivateKey, theirOneTimePreKey);
      ikm = Uint8List(128);
      ikm.setRange(0, 32, dh1);
      ikm.setRange(32, 64, dh2);
      ikm.setRange(64, 96, dh3);
      ikm.setRange(96, 128, dh4);
    } else {
      ikm = Uint8List(96);
      ikm.setRange(0, 32, dh1);
      ikm.setRange(32, 64, dh2);
      ikm.setRange(64, 96, dh3);
    }

    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(ikm, 64, utf8.encode('X3DH')));
    return hkdf.process(Uint8List(0));
  }

  /// X3DH receiver (matching DH operations from B's keys).
  Uint8List calculateX3DHSecretReceiver({
    required Uint8List myIdentityPrivateKey,
    required Uint8List mySignedPreKeyPrivate,
    Uint8List? myOneTimePreKeyPrivate,
    required Uint8List theirIdentityPublicKey,
    required Uint8List theirEphemeralPublicKey,
  }) {
    final dh1 =
        calculateSharedSecret(mySignedPreKeyPrivate, theirIdentityPublicKey);
    final dh2 =
        calculateSharedSecret(myIdentityPrivateKey, theirEphemeralPublicKey);
    final dh3 =
        calculateSharedSecret(mySignedPreKeyPrivate, theirEphemeralPublicKey);

    late Uint8List ikm;
    if (myOneTimePreKeyPrivate != null) {
      final dh4 =
          calculateSharedSecret(myOneTimePreKeyPrivate, theirEphemeralPublicKey);
      ikm = Uint8List(128);
      ikm.setRange(0, 32, dh1);
      ikm.setRange(32, 64, dh2);
      ikm.setRange(64, 96, dh3);
      ikm.setRange(96, 128, dh4);
    } else {
      ikm = Uint8List(96);
      ikm.setRange(0, 32, dh1);
      ikm.setRange(32, 64, dh2);
      ikm.setRange(64, 96, dh3);
    }

    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(ikm, 64, utf8.encode('X3DH')));
    return hkdf.process(Uint8List(0));
  }

  Map<String, Uint8List> generateEphemeralKeyPair() {
    final privateKey = _generateRandom32Bytes();
    final publicKey = derivePublicKey(privateKey);
    return {'private': privateKey, 'public': publicKey};
  }

  Uint8List deriveRootSeed(String mnemonic) {
    return bip39.mnemonicToSeed(mnemonic);
  }

  Uint8List deriveMasterKey(Uint8List seed, String salt) {
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA512Digest(), 128))
      ..init(Pbkdf2Parameters(utf8.encode(salt), pbkdf2Iterations, 32));
    return pbkdf2.process(seed);
  }

  Uint8List derivePrivateKey(Uint8List masterKey, String label) {
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(masterKey, 32, utf8.encode(label)));
    return hkdf.process(Uint8List(0));
  }

  Uint8List derivePublicKey(Uint8List privateKey) {
    final privKeyNum = BigInt.parse(hexEncode(privateKey), radix: 16);
    final pubPoint = _domainParams.G * privKeyNum;
    return pubPoint!.getEncoded(false);
  }

  /// ECDH shared secret (x-coordinate, 32 bytes).
  Uint8List calculateSharedSecret(
      Uint8List myPrivateKey, Uint8List theirPublicKey) {
    final privKeyNum = BigInt.parse(hexEncode(myPrivateKey), radix: 16);
    final pubPoint = _domainParams.curve.decodePoint(theirPublicKey);
    final sharedPoint = pubPoint! * privKeyNum;
    final sharedSecret = sharedPoint!.x!.toBigInteger()!;

    var secretBytes = _bigIntToUint8List(sharedSecret);
    if (secretBytes.length > 32) {
      secretBytes = secretBytes.sublist(secretBytes.length - 32);
    } else if (secretBytes.length < 32) {
      final padded = Uint8List(32);
      padded.setRange(32 - secretBytes.length, 32, secretBytes);
      secretBytes = padded;
    }
    return secretBytes;
  }

  Uint8List deriveConversationKey(
      Uint8List sharedSecret, String conversationId) {
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(sharedSecret, 32, utf8.encode(conversationId)));
    return hkdf.process(Uint8List(0));
  }

  Uint8List generateGroupSessionKey() {
    final key = Uint8List(32);
    final random = Random.secure();
    for (var i = 0; i < 32; i++) {
      key[i] = random.nextInt(256);
    }
    return key;
  }

  Uint8List encryptBytesForRecipient(Uint8List data, Uint8List myPrivateKey,
      Uint8List theirPublicKey, String contextId) {
    final sharedSecret = calculateSharedSecret(myPrivateKey, theirPublicKey);
    final key = deriveConversationKey(sharedSecret, contextId);
    final encryptedMap = encryptGCM(data, key);
    final nonce = encryptedMap['nonce']!;
    final ciphertext = encryptedMap['ciphertext']!;
    final result = Uint8List(nonce.length + ciphertext.length);
    result.setRange(0, nonce.length, nonce);
    result.setRange(nonce.length, result.length, ciphertext);
    return result;
  }

  Uint8List? decryptBytesFromSender(Uint8List encryptedBlob,
      Uint8List myPrivateKey, Uint8List theirPublicKey, String contextId) {
    if (encryptedBlob.length < 12) return null;
    final nonce = encryptedBlob.sublist(0, 12);
    final ciphertext = encryptedBlob.sublist(12);
    final sharedSecret = calculateSharedSecret(myPrivateKey, theirPublicKey);
    final key = deriveConversationKey(sharedSecret, contextId);
    return decryptGCM(ciphertext, key, nonce);
  }

  Uint8List encryptGroupMessage(
      String content, Uint8List groupSessionKey, String groupId) {
    final key = deriveConversationKey(groupSessionKey, groupId);
    final encryptedMap = encryptGCM(utf8.encoder.convert(content), key);
    final nonce = encryptedMap['nonce']!;
    final ciphertext = encryptedMap['ciphertext']!;
    final result = Uint8List(nonce.length + ciphertext.length);
    result.setRange(0, nonce.length, nonce);
    result.setRange(nonce.length, result.length, ciphertext);
    return result;
  }

  String? decryptGroupMessage(
      Uint8List encryptedBlob, Uint8List groupSessionKey, String groupId) {
    if (encryptedBlob.length < 12) return null;
    final nonce = encryptedBlob.sublist(0, 12);
    final ciphertext = encryptedBlob.sublist(12);
    final key = deriveConversationKey(groupSessionKey, groupId);
    final plaintextBytes = decryptGCM(ciphertext, key, nonce);
    if (plaintextBytes == null) return null;
    return utf8.decode(plaintextBytes);
  }

  Uint8List encryptQrSessionMessage(
      String content, Uint8List sessionKey, String sessionToken) {
    final key = deriveConversationKey(sessionKey, sessionToken);
    final encryptedMap = encryptGCM(utf8.encoder.convert(content), key);
    final nonce = encryptedMap['nonce']!;
    final ciphertext = encryptedMap['ciphertext']!;
    final result = Uint8List(nonce.length + ciphertext.length);
    result.setRange(0, nonce.length, nonce);
    result.setRange(nonce.length, result.length, ciphertext);
    return result;
  }

  String? decryptQrSessionMessage(
      Uint8List encryptedBlob, Uint8List sessionKey, String sessionToken) {
    if (encryptedBlob.length < 12) return null;
    final nonce = encryptedBlob.sublist(0, 12);
    final ciphertext = encryptedBlob.sublist(12);
    final key = deriveConversationKey(sessionKey, sessionToken);
    final plaintextBytes = decryptGCM(ciphertext, key, nonce);
    if (plaintextBytes == null) return null;
    return utf8.decode(plaintextBytes);
  }

  Uint8List encryptMessage(String plaintext, Uint8List myPrivateKey,
      Uint8List theirPublicKey, String conversationId) {
    final sharedSecret = calculateSharedSecret(myPrivateKey, theirPublicKey);
    final messageKey = deriveConversationKey(sharedSecret, conversationId);
    final encryptedMap = encryptGCM(utf8.encoder.convert(plaintext), messageKey);
    final nonce = encryptedMap['nonce']!;
    final ciphertext = encryptedMap['ciphertext']!;
    final result = Uint8List(nonce.length + ciphertext.length);
    result.setRange(0, nonce.length, nonce);
    result.setRange(nonce.length, result.length, ciphertext);
    return result;
  }

  String? decryptMessage(Uint8List encryptedBlob, Uint8List myPrivateKey,
      Uint8List theirPublicKey, String conversationId) {
    if (encryptedBlob.length < 12) return null;
    final nonce = encryptedBlob.sublist(0, 12);
    final ciphertext = encryptedBlob.sublist(12);
    final sharedSecret = calculateSharedSecret(myPrivateKey, theirPublicKey);
    final messageKey = deriveConversationKey(sharedSecret, conversationId);
    final plaintextBytes = decryptGCM(ciphertext, messageKey, nonce);
    if (plaintextBytes == null) return null;
    return utf8.decode(plaintextBytes);
  }

  /// AES-256-GCM, random 96-bit nonce, 128-bit tag, optional [aad].
  Map<String, Uint8List> encryptGCM(
    Uint8List plaintext,
    Uint8List key, {
    Uint8List? aad,
  }) {
    final nonce = _generateRandomNonce(12);
    final gcm = GCMBlockCipher(AESEngine())
      ..init(
        true,
        AEADParameters(KeyParameter(key), 128, nonce, aad ?? Uint8List(0)),
      );
    final ciphertext = gcm.process(plaintext);
    return {
      'nonce': nonce,
      'ciphertext': ciphertext,
    };
  }

  /// Returns null on tag/AAD mismatch.
  Uint8List? decryptGCM(
    Uint8List ciphertext,
    Uint8List key,
    Uint8List nonce, {
    Uint8List? aad,
  }) {
    try {
      final gcm = GCMBlockCipher(AESEngine())
        ..init(
          false,
          AEADParameters(KeyParameter(key), 128, nonce, aad ?? Uint8List(0)),
        );
      return gcm.process(ciphertext);
    } catch (_) {
      return null;
    }
  }

  Uint8List _generateRandomNonce(int length) {
    final nonce = Uint8List(length);
    final random = Random.secure();
    for (var i = 0; i < length; i++) {
      nonce[i] = random.nextInt(256);
    }
    return nonce;
  }

  Uint8List _bigIntToUint8List(BigInt bigInt) {
    final hexString = bigInt
        .toRadixString(16)
        .padLeft((bigInt.bitLength + 7) ~/ 8 * 2, '0');
    return hexDecode(hexString);
  }

  String hexEncode(Uint8List data) =>
      data.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  Uint8List hexDecode(String hex) {
    final bytes = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return bytes;
  }

  String base64Encode(Uint8List data) => base64.encode(data);
  Uint8List base64Decode(String data) => base64.decode(data);

  /// Per-slot AES key: salt = slotIndex BE32, info = `qr_slot_v1`.
  static Uint8List deriveQrSlotKey(
    String sessionToken,
    int slotIndex,
    String sessionKeyBase64,
  ) {
    final sessionKey = base64.decode(sessionKeyBase64);
    final salt =
        (ByteData(4)..setUint32(0, slotIndex, Endian.big)).buffer.asUint8List();
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(sessionKey, 32, utf8.encode('qr_slot_v1'), salt));
    return hkdf.process(Uint8List(0));
  }

  /// v2 per-lane key from an ECDH secret (creator × scanner), so other
  /// scanners of the same QR cannot derive it. salt = slotIndex BE32,
  /// info = `qr_slot_v2`.
  static Uint8List deriveQrSlotKeyV2(Uint8List sharedSecret, int slotIndex) {
    final salt =
        (ByteData(4)..setUint32(0, slotIndex, Endian.big)).buffer.asUint8List();
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(sharedSecret, 32, utf8.encode('qr_slot_v2'), salt));
    return hkdf.process(Uint8List(0));
  }

  /// Per-message key (salt = messageId, info = `qr_msg_v1`) so a captured
  /// blob cannot be replayed under a different message id.
  static Uint8List deriveQrMessageKey(Uint8List slotKey, String messageId) {
    final hkdf = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(
        slotKey,
        32,
        utf8.encode('qr_msg_v1'),
        utf8.encode(messageId),
      ));
    return hkdf.process(Uint8List(0));
  }

  /// AES-GCM associated data binding lane, sender and message id.
  static Uint8List qrMessageAad({
    required int slotIndex,
    required String sender,
    required String messageId,
  }) {
    return Uint8List.fromList(
        utf8.encode('qr_v2|$slotIndex|$sender|$messageId'));
  }

  static String? decryptQrBlob(String blob, Uint8List slotKey) {
    try {
      final blobBytes = base64.decode(blob);
      if (blobBytes.length < 12) return null;
      final nonce = blobBytes.sublist(0, 12);
      final ciphertext = blobBytes.sublist(12);
      final gcm = GCMBlockCipher(AESEngine())
        ..init(false,
            AEADParameters(KeyParameter(slotKey), 128, nonce, Uint8List(0)));
      final plainBytes = gcm.process(ciphertext);
      return utf8.decode(plainBytes);
    } catch (_) {
      return null;
    }
  }
}
