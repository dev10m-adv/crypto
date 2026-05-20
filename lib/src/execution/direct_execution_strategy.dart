import '../core/contracts/i_execution_strategy.dart';

/// Runs all work inline on the calling isolate.
///
/// Use this strategy for providers that already manage their own concurrency
/// (e.g. the OpenPGP worker-pool adapter). Applying an additional isolate
/// layer on top of a pool-backed provider would be counterproductive.
class DirectExecutionStrategy implements IExecutionStrategy {
  const DirectExecutionStrategy();

  @override
  Future<R> execute<R>(Future<R> Function() work, {int dataSizeHint = 0}) =>
      work();
}
