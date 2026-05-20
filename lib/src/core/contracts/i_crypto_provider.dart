import 'dart:typed_data';
import '../models/crypto_algorithm.dart';
import '../models/crypto_key.dart';
import '../models/key_generation_params.dart';
import '../models/signature_verification_result.dart';

/// Contract every cryptographic provider must satisfy.
///
/// Implementations are responsible for all algorithm-specific logic.
/// The SDK core routes requests through [ICryptoProvider] without any
/// knowledge of the underlying algorithm.
abstract interface class ICryptoProvider {
  /// The algorithm this provider handles.
  CryptoAlgorithm get algorithm;

  /// Encrypts [plaintext] so that each key in [recipientPublicKeys] can
  /// decrypt it.
  Future<Uint8List> encrypt({
    required Uint8List plaintext,
    required List<CryptoKey> recipientPublicKeys,
  });

  /// Decrypts [ciphertext] using [privateKey].
  /// [passphrase] is required for algorithms that protect private keys
  /// with a passphrase (e.g. OpenPGP).
  Future<Uint8List> decrypt({
    required Uint8List ciphertext,
    required CryptoKey privateKey,
    String? passphrase,
  });

  /// Signs [data] with [signingKey] and returns the detached signature bytes.
  Future<Uint8List> sign({
    required Uint8List data,
    required CryptoKey signingKey,
    String? passphrase,
  });

  /// Verifies [signature] over [data] using [publicKey].
  Future<SignatureVerificationResult> verify({
    required Uint8List data,
    required Uint8List signature,
    required CryptoKey publicKey,
  });

  /// Generates a new key pair according to [params].
  Future<CryptoKeyPair> generateKeyPair(KeyGenerationParams params);

  /// Wraps raw [keyBytes] as a typed public [CryptoKey] for this algorithm.
  Future<CryptoKey> importPublicKey(Uint8List keyBytes);

  /// Wraps raw [keyBytes] as a typed private [CryptoKey] for this algorithm.
  Future<CryptoKey> importPrivateKey(Uint8List keyBytes);

  /// Serialises [key] (public side) to its canonical wire format.
  Uint8List exportPublicKey(CryptoKey key);

  /// Serialises [key] (private side) to its canonical wire format.
  Uint8List exportPrivateKey(CryptoKey key);
}
