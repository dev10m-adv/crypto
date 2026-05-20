/// Controls how the SDK dispatches expensive crypto work.
///
/// The SDK passes [work] through the active strategy so callers can choose
/// between inline execution ([DirectExecutionStrategy]) and offloading to a
/// fresh Dart isolate ([IsolateExecutionStrategy]).
abstract interface class IExecutionStrategy {
  /// Executes [work] according to the strategy.
  ///
  /// [dataSizeHint] is an advisory payload size (bytes) that strategies may
  /// use to decide whether offloading is worthwhile.
  Future<R> execute<R>(Future<R> Function() work, {int dataSizeHint = 0});
}
