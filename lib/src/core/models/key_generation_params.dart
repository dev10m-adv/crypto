import 'package:openpgp/openpgp.dart';

/// Base class for algorithm-specific key-generation parameters.
///
/// Pass a concrete subclass to [ICryptoProvider.generateKeyPair].
abstract class KeyGenerationParams {
  const KeyGenerationParams();
}

/// Cryptographic options for OpenPGP key generation.
///
/// All fields are optional and default to the recommended secure values
/// (EdDSA / Curve25519 / SHA-256 / AES-256 / ZLIB level 6).
class PgpKeyOptions {
  /// Public-key algorithm. Defaults to [Algorithm.EDDSA].
  final Algorithm algorithm;

  /// Elliptic curve. Defaults to [Curve.CURVE25519].
  final Curve curve;

  /// Hash algorithm used for signatures. Defaults to [Hash.SHA256].
  final Hash hash;

  /// Symmetric cipher for payload encryption. Defaults to [Cipher.AES256].
  final Cipher cipher;

  /// Compression algorithm applied before encryption. Defaults to [Compression.ZLIB].
  final Compression compression;

  /// Compression level (0–9). Defaults to 6.
  final int compressionLevel;

  const PgpKeyOptions({
    this.algorithm = Algorithm.EDDSA,
    this.curve = Curve.CURVE25519,
    this.hash = Hash.SHA256,
    this.cipher = Cipher.AES256,
    this.compression = Compression.ZLIB,
    this.compressionLevel = 6,
  });
}

/// Parameters for generating an OpenPGP key pair.
class PgpKeyGenerationParams extends KeyGenerationParams {
  /// The human-readable name for the key's UID (e.g. "Alice Smith").
  final String name;

  /// The email address bound to the key's UID.
  final String email;

  /// The passphrase used to protect the private key.
  final String passphrase;

  /// Cryptographic options for key generation.
  ///
  /// Omit to use the secure defaults (EdDSA / Curve25519 / SHA-256 / AES-256 / ZLIB level 6).
  final PgpKeyOptions keyOptions;

  const PgpKeyGenerationParams({
    required this.name,
    required this.email,
    required this.passphrase,
    this.keyOptions = const PgpKeyOptions(),
  });
}

/// Parameters for generating an S/MIME (RSA 2048 / X.509) key pair.
class SmimeKeyGenerationParams extends KeyGenerationParams {
  /// The Common Name (CN) field in the X.509 certificate subject.
  final String commonName;

  /// The email address bound to the certificate's Subject Alternative Name.
  final String email;

  const SmimeKeyGenerationParams({
    required this.commonName,
    required this.email,
  });
}
