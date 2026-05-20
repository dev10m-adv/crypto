import '../models/crypto_algorithm.dart';

/// Root of the SDK exception hierarchy.
///
/// All SDK-thrown errors extend [CryptoException]. Catch this type to handle
/// any SDK error, or catch a specific subclass for targeted recovery.
sealed class CryptoException implements Exception {
  /// Human-readable description of what went wrong.
  final String message;

  const CryptoException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown when a crypto operation is attempted before [CryptoSdk.initialize]
/// has been called.
final class SdkNotInitializedException extends CryptoException {
  const SdkNotInitializedException()
      : super(
          'CryptoSdk has not been initialized. '
          'Call CryptoSdk.initialize() first.',
        );
}

/// Thrown when the SDK is asked to perform an operation for an algorithm that
/// has no registered [ICryptoProvider].
final class ProviderNotRegisteredException extends CryptoException {
  /// The algorithm that has no provider.
  final CryptoAlgorithm algorithm;

  ProviderNotRegisteredException(this.algorithm)
      : super('No provider registered for algorithm: ${algorithm.name}');
}

/// Thrown when a cryptographic operation (encrypt / decrypt / sign / verify)
/// fails due to an underlying implementation error.
final class CryptoOperationException extends CryptoException {
  /// The algorithm that produced the error, if known.
  final CryptoAlgorithm? algorithm;

  /// The original error that caused this exception, if available.
  final Object? cause;

  const CryptoOperationException(
    super.message, {
    this.algorithm,
    this.cause,
  });
}

/// Thrown when an invalid argument is supplied to a crypto operation
/// (e.g. wrong key type, missing passphrase, empty recipient list).
final class CryptoArgumentException extends CryptoException {
  const CryptoArgumentException(super.message);
}

/// Thrown when raw key bytes cannot be parsed or are structurally invalid.
final class KeyImportException extends CryptoException {
  /// The algorithm the import was attempted for, if known.
  final CryptoAlgorithm? algorithm;

  const KeyImportException(super.message, {this.algorithm});
}

/// Thrown when a secure-storage read or write operation fails.
final class StorageException extends CryptoException {
  const StorageException(super.message);
}
