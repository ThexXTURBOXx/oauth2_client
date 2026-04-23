import 'dart:convert';

import 'package:http/http.dart' as http;

/// Represents the base response for the OAuth 2 requests.
/// see https://tools.ietf.org/html/rfc6749#section-5.2
class OAuth2Response {
  Map<String, dynamic> respMap = {};

  OAuth2Response();

  OAuth2Response.fromMap(Map<String, dynamic> map) {
    respMap = map;
  }

  OAuth2Response.errorResponse(
      {int httpStatusCode = 404,
      String? error,
      String? errorDescription,
      String? errorUri}) {
    respMap = {
      'http_status_code': httpStatusCode,
      'error': error,
      'error_description': errorDescription,
      'errorUri': errorUri
    };
  }

  factory OAuth2Response.fromHttpResponse(http.Response response) {
    OAuth2Response resp;

    var defMap = {'http_status_code': response.statusCode};

    if (response.body != '') {
      resp = OAuth2Response.fromMap({...jsonDecode(response.body), ...defMap});
    } else {
      resp = OAuth2Response.fromMap(defMap);
    }

    return resp;
  }

  Map<String, dynamic> toMap() {
    return respMap;
  }

  dynamic getRespField(String fieldName) {
    return respMap[fieldName];
  }

  ///Checks if the access token request returned a valid status code
  bool isValid() {
    return httpStatusCode == 200 && (error == null || error!.isEmpty);
  }

  int get httpStatusCode {
    return respMap['http_status_code'] ?? 200;
  }

  String? get error {
    return respMap['error'];
  }

  String? get errorDescription {
    return respMap['error_description'];
  }

  String? get errorUri {
    return respMap['errorUri'];
  }

  @override
  String toString() {
    if (httpStatusCode == 200) {
      return 'Request ok';
    } else {
      return 'HTTP $httpStatusCode - ${error ?? ''} ${errorDescription ?? ''}';
    }
  }
}
