import '../models/crypto_key.dart';
import '../models/key_metadata.dart';

/// Optional interface for providers that can introspect key material.
///
/// Not every [ICryptoProvider] is required to implement this. Callers should
/// check via `provider is IKeyInspectionProvider` before use, or rely on
/// [CryptoSdk.getPublicKeyMetadata] / [CryptoSdk.getPrivateKeyMetadata] which
/// throw [CryptoOperationException] when the registered provider does not
/// support inspection.
///
/// Concrete return types per algorithm:
/// | Algorithm | Public                    | Private                    |
/// |-----------|---------------------------|----------------------------|
/// | OpenPGP   | [OpenPgpPublicKeyMetadata] | [OpenPgpPrivateKeyMetadata] |
/// | S/MIME    | [SmimePublicKeyMetadata]   | [SmimePrivateKeyMetadata]   |
abstract interface class IKeyInspectionProvider {
  /// Returns structured metadata for the given public [key].
  Future<KeyMetadataBase> getPublicKeyMetadata(CryptoKey key);

  /// Returns structured metadata for the given private [key].
  Future<KeyMetadataBase> getPrivateKeyMetadata(CryptoKey key);
}
