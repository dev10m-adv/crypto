import '../contracts/i_crypto_provider.dart';
import '../exceptions/crypto_exceptions.dart';
import '../models/crypto_algorithm.dart';

/// Internal registry that maps [CryptoAlgorithm] values to their
/// [ICryptoProvider] implementations.
///
/// The SDK maintains one [ProviderRegistry] per [CryptoSdk] instance.
/// Consumers interact with it indirectly via [CryptoSdk.registerProvider] and
/// [CryptoSdk.unregisterProvider].
class ProviderRegistry {
  final Map<CryptoAlgorithm, ICryptoProvider> _providers = {};

  /// Registers [provider], replacing any existing provider for the same
  /// algorithm.
  void register(ICryptoProvider provider) =>
      _providers[provider.algorithm] = provider;

  /// Removes the provider registered for [algorithm]. No-op if absent.
  void unregister(CryptoAlgorithm algorithm) => _providers.remove(algorithm);

  /// Returns the provider for [algorithm], or null if not registered.
  ICryptoProvider? find(CryptoAlgorithm algorithm) => _providers[algorithm];

  /// Returns the provider for [algorithm], throwing
  /// [ProviderNotRegisteredException] if not registered.
  ICryptoProvider require(CryptoAlgorithm algorithm) =>
      find(algorithm) ?? (throw ProviderNotRegisteredException(algorithm));

  /// Returns true if a provider is registered for [algorithm].
  bool has(CryptoAlgorithm algorithm) => _providers.containsKey(algorithm);

  /// All algorithms currently registered in this registry.
  List<CryptoAlgorithm> get registeredAlgorithms =>
      List.unmodifiable(_providers.keys);
}
