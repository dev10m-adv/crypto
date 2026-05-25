import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import '../core/contracts/i_storage_provider.dart';

/// [ISecureStorageProvider] backed by [FlutterSecureStorage].
///
/// Platform behaviour:
///   - iOS / macOS: stores values in the Keychain.
///   - Android: uses EncryptedSharedPreferences.
///   - Linux / Windows / macOS desktop: uses the platform credential store.
///
/// Pass a custom [FlutterSecureStorage] instance to control Android options
/// (e.g. `encryptedSharedPreferences: true`) or to supply an in-memory mock
/// during testing.
class FlutterSecureStorageProvider implements ISecureStorageProvider {
  final FlutterSecureStorage _storage;

  FlutterSecureStorageProvider({FlutterSecureStorage? storage})
    : _storage = storage ?? const FlutterSecureStorage();

  @override
  Future<void> write({required String key, required String value}) =>
      _storage.write(key: key, value: value);

  @override
  Future<String?> read({required String key}) => _storage.read(key: key);

  @override
  Future<bool> containsKey({required String key}) =>
      _storage.containsKey(key: key);

  @override
  Future<void> delete({required String key}) => _storage.delete(key: key);

  @override
  Future<void> deleteAll() => _storage.deleteAll();

  @override
  Future<List<String>> readAllKeys() =>
      _storage.readAll().then((map) => map.keys.toList());
}
