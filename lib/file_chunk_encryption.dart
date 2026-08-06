import 'dart:async';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Per-chunk AES-256-GCM for large uploads (pure Dart [AesGcm]).
///
/// Wire: nonce(12) || ciphertext || tag(16).
/// Nonce: 8 random bytes + 4-byte big-endian chunk index.
class FileChunkEncryption {
  FileChunkEncryption._();
  static final FileChunkEncryption instance = FileChunkEncryption._();

  static final _aesGcm = AesGcm.with256bits();

  static const int kChunkSize = 4 * 1024 * 1024;
  static const int kLargeChunkSize = 16 * 1024 * 1024;

  static int chunkSizeFor({required bool large}) =>
      large ? kLargeChunkSize : kChunkSize;

  static const int _poolSize = 8;
  int _slots = _poolSize;
  final _waiters = <Completer<void>>[];

  Future<T> _withSlot<T>(Future<T> Function() work) async {
    await _acquire();
    try {
      return await work();
    } finally {
      _release();
    }
  }

  Future<void> _acquire() async {
    if (_slots > 0) {
      _slots--;
      return;
    }
    final c = Completer<void>();
    _waiters.add(c);
    await c.future;
  }

  void _release() {
    if (_waiters.isNotEmpty) {
      _waiters.removeAt(0).complete();
    } else {
      _slots++;
    }
  }

  Future<Uint8List> encryptChunk({
    required Uint8List chunkData,
    required Uint8List fileKey,
    required int chunkIndex,
  }) {
    return _withSlot(() => _encrypt(chunkData, fileKey, chunkIndex));
  }

  Future<Uint8List> decryptChunk({
    required Uint8List encrypted,
    required Uint8List fileKey,
  }) {
    return _withSlot(() => _decrypt(encrypted, fileKey));
  }

  Future<Uint8List> _encrypt(
    Uint8List chunkData,
    Uint8List fileKey,
    int chunkIndex,
  ) async {
    if (fileKey.length != 32) {
      throw ArgumentError('File key must be 32 bytes for AES-256');
    }

    final nonce = _buildNonce(chunkIndex);
    final box = await _aesGcm.encrypt(
      chunkData,
      secretKey: SecretKey(fileKey),
      nonce: nonce,
    );

    final out = Uint8List(12 + box.cipherText.length + box.mac.bytes.length);
    out.setRange(0, 12, nonce);
    out.setRange(12, 12 + box.cipherText.length, box.cipherText);
    out.setRange(
      12 + box.cipherText.length,
      out.length,
      box.mac.bytes,
    );
    return out;
  }

  Future<Uint8List> _decrypt(Uint8List encrypted, Uint8List fileKey) async {
    if (fileKey.length != 32 || encrypted.length < 29) {
      return Uint8List(0);
    }

    final nonce = encrypted.sublist(0, 12);
    final rest = encrypted.sublist(12);
    final macBytes = rest.sublist(rest.length - 16);
    final cipherText = rest.sublist(0, rest.length - 16);

    final plain = await _aesGcm.decrypt(
      SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes)),
      secretKey: SecretKey(fileKey),
    );
    return Uint8List.fromList(plain);
  }

  static Uint8List _buildNonce(int chunkIndex) {
    final nonce = Uint8List(12);
    final rand = Random.secure();
    for (int i = 0; i < 8; i++) {
      nonce[i] = rand.nextInt(256);
    }
    nonce[8] = (chunkIndex >> 24) & 0xFF;
    nonce[9] = (chunkIndex >> 16) & 0xFF;
    nonce[10] = (chunkIndex >> 8) & 0xFF;
    nonce[11] = chunkIndex & 0xFF;
    return nonce;
  }
}
