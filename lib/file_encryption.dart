import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Whole-file AES-256-GCM. Wire: nonce(12) || ciphertext || tag(16).
class FileEncryption {
  static Random? _random;

  static Random get _secureRandom {
    _random ??= Random.secure();
    return _random!;
  }

  static Uint8List encryptFileBytes(Uint8List fileBytes, Uint8List messageKey) {
    if (messageKey.length != 32) {
      throw ArgumentError('Message key must be 32 bytes for AES-256');
    }

    final nonce = Uint8List(12);
    for (int i = 0; i < nonce.length; i++) {
      nonce[i] = _secureRandom.nextInt(256);
    }

    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        true,
        AEADParameters(
          KeyParameter(messageKey),
          128,
          nonce,
          Uint8List(0),
        ),
      );

    final ciphertext = cipher.process(fileBytes);
    final result = BytesBuilder();
    result.add(nonce);
    result.add(ciphertext);
    return result.toBytes();
  }

  static Uint8List decryptFileBytes(
      Uint8List encryptedData, Uint8List messageKey) {
    if (encryptedData.length < 28) {
      throw ArgumentError('Encrypted data is too short');
    }

    final nonce = encryptedData.sublist(0, 12);
    final ciphertext = encryptedData.sublist(12);

    final cipher = GCMBlockCipher(AESEngine())
      ..init(
        false,
        AEADParameters(
          KeyParameter(messageKey),
          128,
          nonce,
          Uint8List(0),
        ),
      );

    return cipher.process(ciphertext);
  }

  static Future<Uint8List> encryptFileIsolate(
      Uint8List fileBytes, Uint8List messageKey) async {
    return Isolate.run(
        () => FileEncryption.encryptFileBytes(fileBytes, messageKey));
  }

  static Future<Uint8List> decryptFileIsolate(
      Uint8List encryptedData, Uint8List messageKey) async {
    return Isolate.run(
        () => FileEncryption.decryptFileBytes(encryptedData, messageKey));
  }
}
