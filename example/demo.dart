/// Demo: X3DH agreement + sealed-sender seal/open with a generated CA.
///
/// Run: dart run example/demo.dart
import 'package:buzzio_crypto/buzzio_crypto.dart';

Future<void> main() async {
  final engine = CryptoEngine(pbkdf2Iterations: 1000);

  print('Buzzio crypto reference demo (not production)\n');

  final aliceIk = engine.generateEphemeralKeyPair();
  final bobIk = engine.generateEphemeralKeyPair();
  final bobSpk = engine.generateEphemeralKeyPair();
  final aliceEph = engine.generateEphemeralKeyPair();

  final skA = engine.calculateX3DHSecret(
    myIdentityPrivateKey: aliceIk['private']!,
    myEphemeralPrivateKey: aliceEph['private']!,
    theirIdentityPublicKey: bobIk['public']!,
    theirSignedPreKey: bobSpk['public']!,
  );
  final skB = engine.calculateX3DHSecretReceiver(
    myIdentityPrivateKey: bobIk['private']!,
    mySignedPreKeyPrivate: bobSpk['private']!,
    theirIdentityPublicKey: aliceIk['public']!,
    theirEphemeralPublicKey: aliceEph['public']!,
  );
  print('X3DH match: ${listEquals(skA, skB)}');

  final ca = engine.generateEphemeralKeyPair();
  final cert = SealedSender.issueDemoCertificate(
    ghostId: 'alice',
    identityPublicKey: aliceIk['public']!,
    caPrivateKey: ca['private']!,
    crypto: engine,
  );

  final sealed = SealedSender(crypto: engine);
  final envelope = sealed.seal(
    certificate: cert,
    innerMessage: {
      'from': 'alice',
      'sender_pk': engine.base64Encode(aliceIk['public']!),
      'text': 'hello over sealed envelope',
    },
    recipientIdentityPub: bobIk['public']!,
  );

  final opened = sealed.open(
    envelopeBase64: envelope,
    recipientIdentityPriv: bobIk['private']!,
    caPublicKey: ca['public']!,
  );

  print('Sealed open OK: ${opened != null}');
  print('Inner text: ${opened?['message']['text']}');
}

bool listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
