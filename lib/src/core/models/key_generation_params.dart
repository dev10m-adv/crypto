/// Base class for algorithm-specific key-generation parameters.
///
/// Pass a concrete subclass to [ICryptoProvider.generateKeyPair].
abstract class KeyGenerationParams {
  const KeyGenerationParams();
}

/// Parameters for generating an OpenPGP (EdDSA / Curve25519) key pair.
class PgpKeyGenerationParams extends KeyGenerationParams {
  /// The human-readable name for the key's UID (e.g. "Alice Smith").
  final String name;

  /// The email address bound to the key's UID.
  final String email;

  /// The passphrase used to protect the private key.
  final String passphrase;

  const PgpKeyGenerationParams({
    required this.name,
    required this.email,
    required this.passphrase,
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
