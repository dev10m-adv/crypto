/// Severity levels for SDK log messages.
enum CryptoLogLevel {
  /// Fine-grained diagnostic information.
  debug,

  /// High-level operational events (pool startup, key generation, etc.).
  info,

  /// Non-fatal issues that the caller should be aware of.
  warning,

  /// Errors that prevented an operation from completing.
  error,
}

/// Callback invoked for every SDK log event.
///
/// [level] is the severity. [message] is a human-readable description.
/// [error] is an optional exception or error object related to the event.
typedef CryptoLogCallback = void Function(
  CryptoLogLevel level,
  String message, [
  Object? error,
]);

/// Internal structured logger used by the SDK.
///
/// Wraps an optional [CryptoLogCallback]. When no callback is provided all
/// log calls are silent, which keeps the SDK zero-overhead in production
/// builds that don't register a logger.
class CryptoLogger {
  final CryptoLogCallback? _callback;

  const CryptoLogger(this._callback);

  /// A no-op logger that discards all messages.
  static const CryptoLogger silent = CryptoLogger(null);

  /// Logs a [CryptoLogLevel.debug] message.
  void debug(String msg) => _callback?.call(CryptoLogLevel.debug, msg);

  /// Logs a [CryptoLogLevel.info] message.
  void info(String msg) => _callback?.call(CryptoLogLevel.info, msg);

  /// Logs a [CryptoLogLevel.warning] message with an optional [error].
  void warning(String msg, [Object? error]) =>
      _callback?.call(CryptoLogLevel.warning, msg, error);

  /// Logs a [CryptoLogLevel.error] message with an optional [error].
  void error(String msg, [Object? error]) =>
      _callback?.call(CryptoLogLevel.error, msg, error);
}
