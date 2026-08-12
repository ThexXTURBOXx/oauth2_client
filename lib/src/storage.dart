import 'base_storage.dart';

/// Implemented in `token_storage.dart` and `secure_storage.dart`.
/// Alternatively, a non-persistent implementation is available in `volatile_storage.dart`.
BaseStorage createStorage() => throw UnsupportedError(
    'Cannot create a storage without dart:js_interop or dart:io.');
