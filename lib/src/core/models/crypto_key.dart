import 'dart:typed_data';
import 'crypto_algorithm.dart';
import 'key_type.dart';

/// An opaque handle for cryptographic key material.
///
/// The [rawBytes] encoding is algorithm-specific:
///   - OpenPGP: UTF-8 bytes of the ASCII-armored key block.
///   - S/MIME:  PEM-encoded X.509 certificate (public) or RSA private key.
///
/// Additional algorithm-specific data (e.g. a signing certificate bundled
/// alongside a private key) is carried in [metadata].
class CryptoKey {
  /// The algorithm this key belongs to.
  final CryptoAlgorithm algorithm;

  /// Whether this is a public or private key.
  final KeyType type;

  /// Raw serialised key bytes in the algorithm's canonical format.
  final Uint8List rawBytes;

  /// Algorithm-specific supplementary data keyed by name.
  ///
  /// Values are immutable [Uint8List] blobs. Common entries:
  ///   - `'certificate'` – PEM certificate bytes bundled with an S/MIME private key.
  ///   - `'caCertificate'` – CA certificate bytes for chain validation.
  final Map<String, Uint8List> metadata;

  CryptoKey({
    required this.algorithm,
    required this.type,
    required this.rawBytes,
    Map<String, Uint8List>? metadata,
  }) : metadata =
            metadata != null ? Map.unmodifiable(metadata) : const {};
}

/// A matched pair of [CryptoKey] objects for the same algorithm and identity.
class CryptoKeyPair {
  /// The public half of the key pair.
  final CryptoKey publicKey;

  /// The private half of the key pair.
  final CryptoKey privateKey;

  const CryptoKeyPair({required this.publicKey, required this.privateKey});
}
