import 'dart:isolate';

import '../core/contracts/i_execution_strategy.dart';
import 'isolate_config.dart';

/// Offloads work to a fresh Dart isolate when the payload exceeds the
/// threshold defined in [IsolateConfig].
///
/// IMPORTANT: Only use this strategy for providers whose [work] closure is
/// isolate-safe — i.e. it captures no live [SendPort], [ReceivePort], or
/// objects backed by native handles. Providers that manage an internal
/// isolate pool (OpenPGP, S/MIME) should use [DirectExecutionStrategy]
/// instead, as those are bound to the main isolate.
class IsolateExecutionStrategy implements IExecutionStrategy {
  /// The configuration that governs the offload decision.
  final IsolateConfig config;

  const IsolateExecutionStrategy(this.config);

  @override
  Future<R> execute<R>(
    Future<R> Function() work, {
    int dataSizeHint = 0,
  }) async {
    if (_shouldOffload(dataSizeHint)) {
      return Isolate.run(work);
    }
    return work();
  }

  bool _shouldOffload(int dataSizeHint) =>
      config.dataSizeThresholdBytes >= 0 &&
      dataSizeHint >= config.dataSizeThresholdBytes;
}
