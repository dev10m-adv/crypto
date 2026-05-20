/// The cryptographic algorithm family handled by a provider.
enum CryptoAlgorithm {
  /// OpenPGP (RFC 4880). Keys are ASCII-armored PGP blocks.
  openPgp,

  /// S/MIME (RFC 5751). Keys are X.509 PEM certificates / private keys.
  smime,
}
