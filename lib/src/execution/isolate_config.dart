/// Configuration for [IsolateExecutionStrategy].
///
/// Controls the payload-size threshold above which work is offloaded to a
/// fresh Dart isolate.
class IsolateConfig {
  /// Payloads larger than this many bytes are offloaded to a new isolate.
  /// Set to -1 to disable offloading entirely (same as [IsolateConfig.disabled]).
  /// Set to 0 to offload every call regardless of size (same as [IsolateConfig.always]).
  final int dataSizeThresholdBytes;

  const IsolateConfig({this.dataSizeThresholdBytes = 100 * 1024});

  /// Never offloads; all work runs inline on the calling isolate.
  static const IsolateConfig disabled =
      IsolateConfig(dataSizeThresholdBytes: -1);

  /// Always offloads; every work item runs in a fresh isolate.
  static const IsolateConfig always =
      IsolateConfig(dataSizeThresholdBytes: 0);
}
