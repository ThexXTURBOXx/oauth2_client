import 'dart:convert';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:random_string/random_string.dart';

/// Default length for the OAuth 2.0 `state` parameter (if enabled).
/// This was increased from 25 to 64 in `oauth2_client` version `5.0.0-alpha.2`
/// in order to improve resilience against brute-forcing.
const defaultStateLength = 64;

/// Default length for the PKCE `code_verifier` parameter (if enabled).
/// This was increased from 80 to 100 in `oauth2_client` version `5.0.0-alpha.2`
/// in order to improve resilience against brute-forcing.
const defaultVerifierLength = 100;

/// Provides various utility functions for OAuth 2.0 processes.
class OAuth2Utils {
  static final CoreRandomProvider _secureRandomProvider =
      CoreRandomProvider.from(Random.secure());

  /// Generates a secure random alpha numeric string of given length.
  /// See also [randomAlphaNumeric].
  static String secureRandomAlphaNumeric(int length) =>
      randomAlphaNumeric(length, provider: _secureRandomProvider);

  /// Generates a code challenge from the [codeVerifier] used for the PKCE extension
  static String generateCodeChallenge(String codeVerifier) {
    var bytes = utf8.encode(codeVerifier);

    var digest = sha256.convert(bytes);

    // Since code challenge must contain only chars in the range ALPHA | DIGIT | "-" | "." | "_" | "~" (see https://tools.ietf.org/html/rfc7636#section-4.2)
    // many OAuth2 servers (read "Google") don't accept the character "=" in base64 encoded strings
    return base64UrlEncode(digest.bytes).replaceAll('=', '');
  }

  /// Converts the given parameter map to a URL query string.
  static String params2qs(Map params) {
    final qsList = <String>[];

    params.forEach((k, v) {
      String val;
      if (v is List) {
        val = v.map((p) => p.trim()).join(' ');
      } else if (v is Map) {
        val = jsonEncode(v);
      } else {
        val = v.trim();
      }
      qsList.add('$k=${Uri.encodeComponent(val)}');
    });

    return qsList.join('&');
  }

  /// Converts the given parameter map to a URL query string and appends it to
  /// the given URL (if non-empty).
  static String addParamsToUrl(String url, Map params) {
    final qs = params2qs(params);

    final appender = url.contains('?') ? '&' : '?';
    if (qs.isNotEmpty) url = '$url$appender$qs';

    return url;
  }
}
