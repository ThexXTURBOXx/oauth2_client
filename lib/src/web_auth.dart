import 'base_web_auth.dart';

/// Implemented in `browser_client.dart` and `io_client.dart`.
BaseWebAuth createWebAuth() => throw UnsupportedError(
    'Cannot create a web auth without package:web or dart:io.');
