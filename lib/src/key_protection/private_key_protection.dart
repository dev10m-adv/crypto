import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Serialisable envelope produced by [encryptPrivateKey].
///
/// Wire format is intentionally stable: all numeric fields are stored by value,
/// all binary fields are base64-encoded strings. The [fromMap] constructor
/// accepts both `kdf_iteration` (legacy) and `kdf_iterations` (canonical) so
/// payloads stored by older versions of the app can still be decrypted.
class EncryptedPrivateKeyPayload {
  final String cipher;
  final String kdf;
  final int iterations;
  final int keyLength;
  final String saltB64;
  final String nonceB64;
  final String cipherTextB64;
  final String macB64;
  final String createdAt;

  const EncryptedPrivateKeyPayload({
    required this.cipher,
    required this.kdf,
    required this.iterations,
    required this.keyLength,
    required this.saltB64,
    required this.nonceB64,
    required this.cipherTextB64,
    required this.macB64,
    required this.createdAt,
  });

  /// Deserialises a payload previously produced by [toMap].
  ///
  /// Throws [FormatException] when any required field is absent or invalid.
  factory EncryptedPrivateKeyPayload.fromMap(Map<String, dynamic> map) {
    final cipher = map['cipher'] as String?;
    final kdf = map['kdf'] as String?;
    // Accept both the legacy singular and the canonical plural key name.
    final iterations = _parseInt(map['kdf_iteration'] ?? map['kdf_iterations']);
    final keyLength = _parseInt(map['kdf_key_length']);
    final saltB64 = map['salt'] as String?;
    final nonceB64 = map['nonce'] as String?;
    final cipherTextB64 = map['cipher_text'] as String?;
    final macB64 = map['mac'] as String?;
    final createdAt = map['created_at'] as String? ?? '';

    if (cipher == null || cipher.isEmpty) {
      throw const FormatException('Missing cipher');
    }
    if (kdf == null || kdf.isEmpty) {
      throw const FormatException('Missing kdf');
    }
    if (iterations == null || iterations <= 0) {
      throw const FormatException('Invalid kdf_iterations');
    }
    if (keyLength == null || keyLength <= 0) {
      throw const FormatException('Invalid kdf_key_length');
    }
    if (saltB64 == null || saltB64.isEmpty) {
      throw const FormatException('Missing salt');
    }
    if (nonceB64 == null || nonceB64.isEmpty) {
      throw const FormatException('Missing nonce');
    }
    if (cipherTextB64 == null || cipherTextB64.isEmpty) {
      throw const FormatException('Missing cipher_text');
    }
    if (macB64 == null || macB64.isEmpty) {
      throw const FormatException('Missing mac');
    }

    return EncryptedPrivateKeyPayload(
      cipher: cipher,
      kdf: kdf,
      iterations: iterations,
      keyLength: keyLength,
      saltB64: saltB64,
      nonceB64: nonceB64,
      cipherTextB64: cipherTextB64,
      macB64: macB64,
      createdAt: createdAt,
    );
  }

  /// Serialises the payload into the server wire format.
  ///
  /// [identity] is any application-level identifier (typically an email
  /// address) used by the server to associate the backup with an account.
  /// [keyType] is an algorithm tag (e.g. `'openpgp'`, `'smime'`).
  Map<String, dynamic> toMap({
    required String identity,
    required String keyType,
  }) {
    return {
      'EmailAddress': identity,
      'key_type': keyType,
      'cipher': cipher,
      'kdf': kdf,
      'kdf_iterations': iterations,
      'kdf_key_length': keyLength,
      'salt': saltB64,
      'nonce': nonceB64,
      'cipher_text': cipherTextB64,
      'mac': macB64,
      'created_at': createdAt,
    };
  }
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Encrypts [privateKey] bytes under [password] using
/// PBKDF2-HMAC-SHA256 (200 000 iterations) + AES-256-GCM.
///
/// The returned [EncryptedPrivateKeyPayload] is safe to serialise and upload
/// to a remote backup service. The raw key never leaves the device in
/// plaintext.
///
/// [password] is a user-supplied secret; the SDK does not store or validate
/// it — key derivation entropy comes entirely from [password] + a fresh
/// 128-bit random salt.
Future<EncryptedPrivateKeyPayload> encryptPrivateKey({
  required Uint8List privateKey,
  required String password,
}) async {
  const iterations = 200000;
  const keyBits = 256;

  final salt = _randomBytes(16);

  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: iterations,
    bits: keyBits,
  );
  final secretKey = await pbkdf2.deriveKey(
    secretKey: SecretKey(utf8.encode(password)),
    nonce: salt,
  );

  final nonce = _randomBytes(12);
  final secretBox = await AesGcm.with256bits().encrypt(
    privateKey,
    secretKey: secretKey,
    nonce: nonce,
  );

  return EncryptedPrivateKeyPayload(
    cipher: 'AES-256-GCM',
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: iterations,
    keyLength: keyBits,
    saltB64: base64Encode(salt),
    nonceB64: base64Encode(secretBox.nonce),
    cipherTextB64: base64Encode(secretBox.cipherText),
    macB64: base64Encode(secretBox.mac.bytes),
    createdAt: DateTime.now().toUtc().toIso8601String(),
  );
}

/// Decrypts an [EncryptedPrivateKeyPayload] (or its raw map form) using
/// [password].
///
/// Throws [WrongPasswordException] when the MAC verification fails (i.e. the
/// password is incorrect or the ciphertext was tampered with).
/// Throws [FormatException] when [payloadMap] is missing required fields.
Future<Uint8List> decryptPrivateKey({
  required Map<String, dynamic> payloadMap,
  required String password,
}) async {
  final p = EncryptedPrivateKeyPayload.fromMap(payloadMap);

  final salt = base64Decode(p.saltB64);
  final nonce = base64Decode(p.nonceB64);
  final cipherText = base64Decode(p.cipherTextB64);
  final macBytes = base64Decode(p.macB64);

  final pbkdf2 = Pbkdf2(
    macAlgorithm: Hmac.sha256(),
    iterations: p.iterations,
    bits: p.keyLength,
  );
  final secretKey = await pbkdf2.deriveKey(
    secretKey: SecretKey(utf8.encode(password)),
    nonce: salt,
  );

  final algorithm = _aesForKeyBits(p.keyLength);
  final box = SecretBox(cipherText, nonce: nonce, mac: Mac(macBytes));

  try {
    final clearBytes = await algorithm.decrypt(box, secretKey: secretKey);
    return Uint8List.fromList(clearBytes);
  } on SecretBoxAuthenticationError {
    throw const WrongPasswordException();
  }
}

// ── Exceptions ─────────────────────────────────────────────────────────────

/// Thrown by [decryptPrivateKey] when AES-GCM authentication fails.
///
/// This almost always means the wrong password was supplied, but it can also
/// indicate ciphertext corruption.
class WrongPasswordException implements Exception {
  const WrongPasswordException();

  @override
  String toString() =>
      'WrongPasswordException: incorrect password or corrupted ciphertext';
}

// ── Internals ───────────────────────────────────────────────────────────────

List<int> _randomBytes(int count) =>
    List<int>.generate(count, (_) => Random.secure().nextInt(256));

AesGcm _aesForKeyBits(int bits) => switch (bits) {
      128 => AesGcm.with128bits(),
      192 => AesGcm.with192bits(),
      256 => AesGcm.with256bits(),
      _ => throw FormatException('Unsupported AES key length: $bits bits'),
    };

int? _parseInt(dynamic value) {
  if (value is int) return value;
  if (value is num) return value.toInt();
  if (value is String) return int.tryParse(value.trim());
  return null;
}
