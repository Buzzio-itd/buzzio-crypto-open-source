import 'dart:typed_data';

import 'package:buzzio_crypto/buzzio_crypto.dart';
import 'package:test/test.dart';

void main() {
  final engine = CryptoEngine(pbkdf2Iterations: 1000);
  Uint8List bytes(String s) => Uint8List.fromList(s.codeUnits);

  group('AES-GCM associated data', () {
    test('round-trips with matching AAD', () {
      final key = engine.generateGroupSessionKey();
      final blob = engine.encryptFast(bytes('hi'), key, aad: bytes('ctx-1'));
      expect(engine.decryptFast(blob, key, aad: bytes('ctx-1')), bytes('hi'));
    });

    test('rejects different or missing AAD', () {
      final key = engine.generateGroupSessionKey();
      final blob = engine.encryptFast(bytes('hi'), key, aad: bytes('ctx-1'));
      expect(engine.decryptFast(blob, key, aad: bytes('ctx-2')), isNull);
      expect(engine.decryptFast(blob, key), isNull);
    });
  });

  group('QR lane v2', () {
    test('both sides derive the same lane key; another lane differs', () {
      final creator = engine.generateEphemeralKeyPair();
      final scanner = engine.generateEphemeralKeyPair();
      final a = engine.calculateSharedSecret(creator['private']!, scanner['public']!);
      final b = engine.calculateSharedSecret(scanner['private']!, creator['public']!);
      expect(CryptoEngine.deriveQrSlotKeyV2(a, 3), CryptoEngine.deriveQrSlotKeyV2(b, 3));
      expect(CryptoEngine.deriveQrSlotKeyV2(a, 3),
          isNot(CryptoEngine.deriveQrSlotKeyV2(a, 4)));
    });

    test('message key + AAD block replay under another id or sender', () {
      final slotKey = engine.generateGroupSessionKey();
      final key = CryptoEngine.deriveQrMessageKey(slotKey, 'm1');
      final aad = CryptoEngine.qrMessageAad(slotIndex: 0, sender: 'creator', messageId: 'm1');
      final blob = engine.encryptFast(bytes('lane hello'), key, aad: aad);

      expect(engine.decryptFast(blob, key, aad: aad), bytes('lane hello'));
      final otherId = CryptoEngine.deriveQrMessageKey(slotKey, 'm2');
      expect(engine.decryptFast(blob, otherId, aad: aad), isNull);
      final otherSender =
          CryptoEngine.qrMessageAad(slotIndex: 0, sender: 'scanner', messageId: 'm1');
      expect(engine.decryptFast(blob, key, aad: otherSender), isNull);
    });
  });

  group('SecurityCodeFingerprint', () {
    test('symmetric, 60 digits, 12 groups', () {
      final a = engine.generateEphemeralKeyPair()['public']!;
      final b = engine.generateEphemeralKeyPair()['public']!;
      final ab = SecurityCodeFingerprint.fromPublicKeys(a, b);
      final ba = SecurityCodeFingerprint.fromPublicKeys(b, a);
      expect(ab.rawDigits, ba.rawDigits);
      expect(ab.rawDigits, hasLength(60));
      expect(ab.grouped.split(' '), hasLength(12));
      expect(ab.matchesScanned(ab.grouped), isTrue);
    });

    test('labeled order is symmetric and key-sensitive', () {
      final a = engine.generateEphemeralKeyPair()['public']!;
      final b = engine.generateEphemeralKeyPair()['public']!;
      final c = engine.generateEphemeralKeyPair()['public']!;
      final x = SecurityCodeFingerprint.fromLabeledKeys(
          idA: 'alice', idB: 'bob', publicKeyA: a, publicKeyB: b);
      final y = SecurityCodeFingerprint.fromLabeledKeys(
          idA: 'bob', idB: 'alice', publicKeyA: b, publicKeyB: a);
      final z = SecurityCodeFingerprint.fromLabeledKeys(
          idA: 'alice', idB: 'bob', publicKeyA: a, publicKeyB: c);
      expect(x.rawDigits, y.rawDigits);
      expect(x.rawDigits, isNot(z.rawDigits));
    });
  });

  group('RoomTransportSeal', () {
    test('round-trips and keeps key version', () {
      final dek = engine.generateGroupSessionKey();
      final env = RoomTransportSeal.seal({'text': 'room hi'}, dek, keyVersion: 7);
      expect(env['kv'], 7);
      expect(RoomTransportSeal.open(env, dek), {'text': 'room hi'});
    });

    test('wrong key or tampered ciphertext returns null', () {
      final dek = engine.generateGroupSessionKey();
      final env = RoomTransportSeal.seal({'text': 'room hi'}, dek);
      expect(RoomTransportSeal.open(env, engine.generateGroupSessionKey()), isNull);
      final ct = env['ct'] as String;
      final tampered = {...env, 'ct': '${ct.substring(0, ct.length - 4)}AAAA'};
      expect(RoomTransportSeal.open(tampered, dek), isNull);
    });
  });

  group('SeedWrapKey', () {
    test('deterministic per label, independent across labels', () {
      final master = engine.generateGroupSessionKey();
      final v1 = SeedWrapKey.derive(master, SeedWrapKey.exampleVaultInfo);
      final v2 = SeedWrapKey.derive(master, SeedWrapKey.exampleVaultInfo);
      final b = SeedWrapKey.derive(master, SeedWrapKey.exampleBackupInfo);
      expect(v1, v2);
      expect(v1, hasLength(32));
      expect(v1, isNot(b));
    });

    test('rejects a short master key', () {
      expect(() => SeedWrapKey.derive(Uint8List(16), 'x'), throwsArgumentError);
    });
  });

  test('sender key public signature check', () async {
    final sk = SenderKeyEngine();
    final bundle = sk.generateSenderKey();
    final msg = await sk.encrypt(
      plaintext: 'sig',
      chainKey: bundle.chainKey,
      chainIndex: 0,
      signingPrivKey: bundle.signingPrivKey,
    );
    expect(sk.verifySignature(msg.ciphertext, msg.signature, bundle.signingPubKey), isTrue);
    final other = sk.generateSenderKey();
    expect(sk.verifySignature(msg.ciphertext, msg.signature, other.signingPubKey), isFalse);
  });
}
