/// Whether a [CryptoKey] holds a public or private key material.
enum KeyType {
  /// Public key — safe to share with third parties.
  publicKey,

  /// Private key — must be kept secret.
  privateKey,
}
