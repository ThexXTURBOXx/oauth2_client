import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Provides various utility functions for OAuth 2.0 processes.
class OAuth2Utils {
  /// Generates a code challenge from the [codeVerifier] used for the PKCE extension
  static String generateCodeChallenge(String codeVerifier) {
    var bytes = utf8.encode(codeVerifier);

    var digest = sha256.convert(bytes);

    var codeChallenge = base64UrlEncode(digest.bytes);

    if (codeChallenge.endsWith('=')) {
      //Since code challenge must contain only chars in the range ALPHA | DIGIT | "-" | "." | "_" | "~" (see https://tools.ietf.org/html/rfc7636#section-4.2)
      //many OAuth2 servers (read "Google") don't accept the "=" at the end of the base64 encoded string
      codeChallenge = codeChallenge.substring(0, codeChallenge.length - 1);
    }

    return codeChallenge;
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
