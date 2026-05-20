import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../../../core/contracts/i_certificate_signing_service.dart';
import '../../../core/logging/crypto_logger.dart';

/// Generates S/MIME (RSA 2048 / X.509) key pairs using the system `openssl` CLI.
///
/// Certificate signing behaviour:
///   1. If a [signingService] is provided and [signingService.signCsr] returns
///      a non-null PEM string, that CA-issued certificate is used.
///   2. Otherwise the generator creates a self-signed certificate valid for
///      365 days.
///
/// All temporary files are isolated in a unique system-temp directory and
/// deleted in a `finally` block regardless of success or failure.
class SmimeCertificateGenerator {
  /// Path to the `openssl` binary. Defaults to `'openssl'` (resolved via PATH).
  final String opensslPath;

  /// Optional CA-signing integration. When provided its [ICertificateSigningService.signCsr]
  /// is called after CSR generation. If it returns null, self-signing is used.
  final ICertificateSigningService? signingService;

  final CryptoLogger _log;

  SmimeCertificateGenerator({
    this.opensslPath = 'openssl',
    this.signingService,
    CryptoLogger logger = CryptoLogger.silent,
  }) : _log = logger;

  /// Generates an RSA 2048-bit private key and an X.509 certificate for
  /// [commonName] / [email].
  ///
  /// Returns a record containing:
  ///   - `privateKey` – raw PEM private-key bytes.
  ///   - `certificatePem` – PEM certificate string (CA-signed or self-signed).
  Future<({Uint8List privateKey, String certificatePem})> generate({
    required String commonName,
    required String email,
  }) async {
    final tmp = await _TempFiles.create();
    try {
      // 1. Generate RSA 2048-bit private key.
      final pKeyResult = await Process.run(opensslPath, [
        'genpkey',
        '-algorithm', 'RSA',
        '-out', tmp.path('private_key.pem'),
        '-pkeyopt', 'rsa_keygen_bits:2048',
      ]);

      if (pKeyResult.exitCode != 0) {
        throw Exception(
          'OpenSSL private key generation failed: ${pKeyResult.stderr}',
        );
      }

      // 2. Generate CSR.
      final csrResult = await Process.run(opensslPath, [
        'req', '-new',
        '-key', tmp.path('private_key.pem'),
        '-out', tmp.path('csr.pem'),
        '-subj', '/CN=$commonName/emailAddress=$email',
      ]);

      if (csrResult.exitCode != 0) {
        throw Exception('OpenSSL CSR generation failed: ${csrResult.stderr}');
      }

      final privateKeyBytes = await tmp.read('private_key.pem');

      // 3. Attempt CA signing if a service is available.
      if (signingService != null) {
        _log.debug('Attempting CA signing for $email');
        final csrPem = utf8.decode(await tmp.read('csr.pem'));
        final signedCert = await signingService!.signCsr(
          csrPem: csrPem,
          email: email,
          commonName: commonName,
        );
        if (signedCert != null) {
          _log.info('CA-signed certificate issued for $email');
          return (privateKey: privateKeyBytes, certificatePem: signedCert);
        }
        _log.warning(
          'CA signing returned null for $email — falling back to self-signed.',
        );
      }

      // 4. Self-sign the certificate (365-day validity).
      final certResult = await Process.run(opensslPath, [
        'x509', '-req',
        '-in', tmp.path('csr.pem'),
        '-signkey', tmp.path('private_key.pem'),
        '-out', tmp.path('certificate.pem'),
        '-days', '365',
      ]);

      if (certResult.exitCode != 0) {
        throw Exception(
          'OpenSSL certificate self-signing failed: ${certResult.stderr}',
        );
      }

      final certPem = utf8.decode(await tmp.read('certificate.pem'));
      _log.info('Self-signed certificate generated for $email');
      return (privateKey: privateKeyBytes, certificatePem: certPem);
    } finally {
      await tmp.cleanup();
    }
  }
}

// ── Temp file management ───────────────────────────────────────────────────

class _TempFiles {
  final Directory dir;

  _TempFiles._(this.dir);

  static Future<_TempFiles> create() async {
    final dir = await Directory.systemTemp.createTemp('smime_gen_');
    return _TempFiles._(dir);
  }

  String path(String name) => '${dir.path}/$name';

  Future<void> write(String name, Uint8List data) =>
      File(path(name)).writeAsBytes(data);

  Future<Uint8List> read(String name) => File(path(name)).readAsBytes();

  Future<void> cleanup() => dir.delete(recursive: true);
}
