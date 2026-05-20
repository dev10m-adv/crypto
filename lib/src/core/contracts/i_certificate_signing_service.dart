/// Optional CA-signing integration for S/MIME certificate generation.
///
/// Implement this interface to integrate with a Certificate Authority that can
/// issue properly signed S/MIME certificates. If [signCsr] returns null, the
/// [SmimeCertificateGenerator] falls back to a self-signed certificate.
///
/// Example:
/// ```dart
/// class MyCaService implements ICertificateSigningService {
///   @override
///   Future<String?> signCsr({
///     required String csrPem,
///     required String email,
///     required String commonName,
///   }) async {
///     final response = await myApiClient.post('/sign-csr', {
///       'csr': csrPem,
///       'email': email,
///       'common_name': commonName,
///     });
///     return response['certificate'] as String?;
///   }
/// }
/// ```
abstract interface class ICertificateSigningService {
  /// Submits [csrPem] to the CA and returns the signed certificate PEM string.
  ///
  /// Return null to signal that CA signing is unavailable and the caller
  /// should fall back to self-signing.
  Future<String?> signCsr({
    required String csrPem,
    required String email,
    required String commonName,
  });
}
