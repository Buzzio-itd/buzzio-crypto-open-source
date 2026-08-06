import 'dart:typed_data';

import 'package:buzzio_crypto/buzzio_crypto.dart';
import 'package:test/test.dart';

void main() {
  final engine = CryptoEngine(pbkdf2Iterations: 1000);

  test('X3DH sender and receiver derive the same secret', () {
    final alice = engine.generateEphemeralKeyPair();
    final bobIk = engine.generateEphemeralKeyPair();
    final bobSpk = engine.generateEphemeralKeyPair();
    final bobOpk = engine.generateEphemeralKeyPair();
    final aliceEph = engine.generateEphemeralKeyPair();

    final senderSk = engine.calculateX3DHSecret(
      myIdentityPrivateKey: alice['private']!,
      myEphemeralPrivateKey: aliceEph['private']!,
      theirIdentityPublicKey: bobIk['public']!,
      theirSignedPreKey: bobSpk['public']!,
      theirOneTimePreKey: bobOpk['public']!,
    );

    final receiverSk = engine.calculateX3DHSecretReceiver(
      myIdentityPrivateKey: bobIk['private']!,
      mySignedPreKeyPrivate: bobSpk['private']!,
      myOneTimePreKeyPrivate: bobOpk['private']!,
      theirIdentityPublicKey: alice['public']!,
      theirEphemeralPublicKey: aliceEph['public']!,
    );

    expect(senderSk, equals(receiverSk));
  });

  test('AES-GCM encryptFast round-trip', () {
    final key = engine.generateGroupSessionKey();
    final plain = Uint8List.fromList('hello sealed world'.codeUnits);
    final blob = engine.encryptFast(plain, key);
    final out = engine.decryptFast(blob, key);
    expect(out, equals(plain));
  });

  test('sealed sender seal/open with demo CA', () {
    final ca = engine.generateEphemeralKeyPair();
    final alice = engine.generateEphemeralKeyPair();
    final bob = engine.generateEphemeralKeyPair();

    final cert = SealedSender.issueDemoCertificate(
      ghostId: 'alice_demo',
      identityPublicKey: alice['public']!,
      caPrivateKey: ca['private']!,
      crypto: engine,
    );

    final sealed = SealedSender(crypto: engine);
    final envelope = sealed.seal(
      certificate: cert,
      innerMessage: {
        'from': 'alice_demo',
        'sender_pk': engine.base64Encode(alice['public']!),
        'body': 'hi bob',
      },
      recipientIdentityPub: bob['public']!,
    );

    final opened = sealed.open(
      envelopeBase64: envelope,
      recipientIdentityPriv: bob['private']!,
      caPublicKey: ca['public']!,
    );

    expect(opened, isNotNull);
    expect(opened!['message']['body'], equals('hi bob'));
    expect(opened['certificate']['gid'], equals('alice_demo'));
  });

  test('file encryption round-trip', () {
    final key = engine.generateGroupSessionKey();
    final data = Uint8List.fromList(List.generate(200, (i) => i % 256));
    final enc = FileEncryption.encryptFileBytes(data, key);
    final dec = FileEncryption.decryptFileBytes(enc, key);
    expect(dec, equals(data));
  });

  test('sender key encrypt/decrypt', () async {
    final sk = SenderKeyEngine();
    final bundle = sk.generateSenderKey();
    var chainKey = bundle.chainKey;
    var index = 0;

    final msg = await sk.encrypt(
      plaintext: 'group hello',
      chainKey: chainKey,
      chainIndex: index,
      signingPrivKey: bundle.signingPrivKey,
    );

    final skipped = <int, Uint8List>{};
    final plain = await sk.decryptAsync(
      message: msg,
      currentChainKey: chainKey,
      currentChainIndex: index,
      signingPubKey: bundle.signingPubKey,
      onChainAdvanced: (newKey, newIndex) async {
        chainKey = newKey;
        index = newIndex;
      },
      getSkippedKey: (i) async => skipped[i],
      saveSkippedKey: (i, k) async {
        skipped[i] = k;
      },
    );

    expect(plain, equals('group hello'));
  });
}
