/// Contract for a secure key-value storage backend.
///
/// Implementations must guarantee that stored data is protected at rest
/// (e.g. OS Keychain, EncryptedSharedPreferences, or equivalent).
abstract interface class ISecureStorageProvider {
  /// Writes [value] under [key], overwriting any existing value.
  Future<void> write({required String key, required String value});

  /// Reads the value stored under [key], or null if absent.
  Future<String?> read({required String key});

  /// Returns true if a value exists for [key].
  Future<bool> containsKey({required String key});

  /// Deletes the value stored under [key]. No-op if the key is absent.
  Future<void> delete({required String key});

  /// Deletes all values in the storage.
  Future<void> deleteAll();
}
