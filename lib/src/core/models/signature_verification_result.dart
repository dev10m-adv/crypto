/// The outcome of a signature verification operation.
class SignatureVerificationResult {
  /// Whether the signature is cryptographically valid.
  final bool isValid;

  /// Human-readable reason why verification failed, or null if [isValid].
  final String? failureReason;

  /// Constructs a successful verification result.
  const SignatureVerificationResult.valid()
      : isValid = true,
        failureReason = null;

  /// Constructs a failed verification result with an optional [failureReason].
  const SignatureVerificationResult.invalid([this.failureReason])
      : isValid = false;

  @override
  String toString() => isValid
      ? 'SignatureVerificationResult.valid'
      : 'SignatureVerificationResult.invalid($failureReason)';
}
