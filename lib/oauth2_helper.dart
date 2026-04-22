import 'package:http/http.dart' as http;
import 'package:oauth2_client/access_token_response.dart';
import 'package:oauth2_client/oauth2_client.dart';
import 'package:oauth2_client/oauth2_exception.dart';
import 'package:oauth2_client/oauth2_response.dart';
import 'package:oauth2_client/src/base_web_auth.dart';
import 'package:oauth2_client/src/token_storage.dart';

/// Helper class for simplifying OAuth2 authorization process.
///
/// Tokens are stored in a secure storage.
/// The helper performs automatic token refreshing upon access token expiration.
/// Moreover it provides methods to perform http post/get calls with automatic Access Token injection in the requests header
///
///
class OAuth2Helper {
  static const authorizationCode = 1;
  static const clientCredentials = 2;
  static const implicitGrant = 3;

  final OAuth2Client client;
  late TokenStorage tokenStorage;

  int grantType;
  String clientId;
  String? clientSecret;
  List<String>? scopes;
  bool enablePKCE;
  bool enableState;

  Function? afterAuthorizationCodeCb;

  Map<String, dynamic>? authCodeParams;
  Map<String, dynamic>? accessTokenParams;
  Map<String, String>? accessTokenHeaders;

  BaseWebAuth? webAuthClient;
  Map<String, dynamic>? webAuthOpts;

  OAuth2Helper(this.client,
      {this.grantType = authorizationCode,
      required this.clientId,
      this.clientSecret,
      this.scopes,
      this.enablePKCE = true,
      this.enableState = true,
      tokenStorage,
      this.afterAuthorizationCodeCb,
      this.authCodeParams,
      this.accessTokenParams,
      this.accessTokenHeaders,
      this.webAuthClient,
      this.webAuthOpts}) {
    this.tokenStorage = tokenStorage ?? TokenStorage(client.tokenUrl);
  }

  /// Returns a previously required token, if any, or requires a new one.
  ///
  /// If a token already exists but is expired, a new token is generated through the refresh_token grant.
  Future<AccessTokenResponse?> getToken({http.Client? httpClient}) async {
    _validateAuthorizationParams();

    var tknResp = await getTokenFromStorage();

    if (tknResp != null) {
      if (tknResp.refreshNeeded()) {
        //The access token is expired
        if (tknResp.hasRefreshToken()) {
          tknResp = await refreshToken(tknResp, httpClient: httpClient);
        } else {
          //No refresh token, fetch a new token
          tknResp = await fetchToken(httpClient: httpClient);
        }
      }
    } else {
      tknResp = await fetchToken(httpClient: httpClient);
    }

    if (!tknResp.isValid()) {
      throw OAuth2Exception(
          'Provider error ${tknResp.httpStatusCode}: ${tknResp.error}',
          errorDescription: tknResp.errorDescription);
    }

    if (!tknResp.isBearer()) {
      throw OAuth2Exception('Only Bearer tokens are currently supported');
    }

    return tknResp;
  }

  /// Returns the previously stored Access Token from the storage, if any
  Future<AccessTokenResponse?> getTokenFromStorage() async {
    return await tokenStorage.getToken(scopes ?? []);
  }

  /// Fetches a new token and saves it in the storage
  Future<AccessTokenResponse> fetchToken({http.Client? httpClient}) async {
    _validateAuthorizationParams();

    AccessTokenResponse tknResp;

    if (grantType == authorizationCode) {
      tknResp = await client.getTokenWithAuthCodeFlow(
          clientId: clientId,
          clientSecret: clientSecret,
          scopes: scopes,
          enablePKCE: enablePKCE,
          enableState: enableState,
          authCodeParams: authCodeParams,
          accessTokenParams: accessTokenParams,
          accessTokenHeaders: accessTokenHeaders,
          afterAuthorizationCodeCb: afterAuthorizationCodeCb,
          webAuthClient: webAuthClient,
          webAuthOpts: webAuthOpts,
          httpClient: httpClient);
    } else if (grantType == clientCredentials) {
      tknResp = await client.getTokenWithClientCredentialsFlow(
          clientId: clientId,
          //The clientSecret param can't be null at this point... It has been validated by the above _validateAuthorizationParams call...
          clientSecret: clientSecret!,
          customHeaders: accessTokenHeaders,
          scopes: scopes,
          httpClient: httpClient);
    } else if (grantType == implicitGrant) {
      tknResp = await client.getTokenWithImplicitGrantFlow(
          clientId: clientId,
          scopes: scopes,
          enableState: enableState,
          webAuthClient: webAuthClient,
          webAuthOpts: webAuthOpts,
          customParams: authCodeParams,
          httpClient: httpClient);
    } else {
      tknResp = AccessTokenResponse.errorResponse();
    }

    if (tknResp.isValid()) {
      await tokenStorage.addToken(tknResp);
    }

    return tknResp;
  }

  /// Performs a refresh_token request using the [refreshToken].
  Future<AccessTokenResponse> refreshToken(AccessTokenResponse curTknResp,
      {http.Client? httpClient}) async {
    AccessTokenResponse? tknResp;
    var refreshToken = curTknResp.refreshToken!;
    try {
      tknResp = await client.refreshToken(refreshToken,
          clientId: clientId,
          clientSecret: clientSecret,
          scopes: curTknResp.scope,
          httpClient: httpClient);
    } catch (_) {
      return await fetchToken(httpClient: httpClient);
    }

    if (tknResp.isValid()) {
      //If the response doesn't contain a refresh token, keep using the current one
      if (!tknResp.hasRefreshToken()) {
        tknResp.refreshToken = refreshToken;
      }

      await tokenStorage.addToken(tknResp);
    } else {
      // invalid_grant is usually produced in this case.
      // Some major backend providers (such as League/oauth2-server) seem
      // to throw invalid_request errors as well, though...
      if (tknResp.error == 'invalid_grant' ||
          tknResp.error == 'invalid_request') {
        //The refresh token is expired too
        await tokenStorage.deleteToken(scopes ?? []);
        //Fetch another access token
        tknResp = await getToken(httpClient: httpClient);
      } else {
        throw OAuth2Exception(tknResp.error ?? 'Error',
            errorDescription: tknResp.errorDescription);
      }
    }

    return tknResp!;
  }

  /// Revokes the previously fetched token
  Future<OAuth2Response> disconnect({http.Client? httpClient}) async {
    httpClient ??= http.Client();

    final tknResp = await tokenStorage.getToken(scopes ?? []);

    if (tknResp != null) {
      await tokenStorage.deleteToken(scopes ?? []);
      return await client.revokeToken(tknResp,
          clientId: clientId,
          clientSecret: clientSecret,
          httpClient: httpClient);
    } else {
      return OAuth2Response();
    }
  }

  Future removeAllTokens() async {
    await tokenStorage.deleteAllTokens();
  }

  /// Performs a POST request to the specified [url], adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.Response> post(String url,
      {Map<String, String>? headers,
      dynamic body,
      http.Client? httpClient}) async {
    return _request('POST', url,
        headers: headers, body: body, httpClient: httpClient);
  }

  /// Performs a PUT request to the specified [url], adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.Response> put(String url,
      {Map<String, String>? headers,
      dynamic body,
      http.Client? httpClient}) async {
    return _request('PUT', url,
        headers: headers, body: body, httpClient: httpClient);
  }

  /// Performs a PATCH request to the specified [url], adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.Response> patch(String url,
      {Map<String, String>? headers,
      dynamic body,
      http.Client? httpClient}) async {
    return _request('PATCH', url,
        headers: headers, body: body, httpClient: httpClient);
  }

  /// Performs a GET request to the specified [url], adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.Response> get(String url,
      {Map<String, String>? headers, http.Client? httpClient}) async {
    return _request('GET', url, headers: headers, httpClient: httpClient);
  }

  /// Performs a DELETE request to the specified [url], adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.Response> delete(String url,
      {Map<String, String>? headers, http.Client? httpClient}) async {
    return _request('DELETE', url, headers: headers, httpClient: httpClient);
  }

  /// Performs a HEAD request to the specified [url], adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.Response> head(String url,
      {Map<String, String>? headers,
      dynamic body,
      http.Client? httpClient}) async {
    return _request('HEAD', url, headers: headers, httpClient: httpClient);
  }

  /// Common method for making http requests
  /// Tries to use a previously fetched token, otherwise fetches a new token by means of a refresh flow or by issuing a new authorization flow
  Future<http.Response> _request(String method, String url,
      {Map<String, String>? headers,
      dynamic body,
      http.Client? httpClient}) async {
    httpClient ??= http.Client();

    headers ??= {};

    sendRequest(accessToken) async {
      http.Response resp;

      headers!['Authorization'] = 'Bearer $accessToken';

      if (method == 'POST') {
        resp = await httpClient!
            .post(Uri.parse(url), body: body, headers: headers);
      } else if (method == 'PUT') {
        resp =
            await httpClient!.put(Uri.parse(url), body: body, headers: headers);
      } else if (method == 'PATCH') {
        resp = await httpClient!
            .patch(Uri.parse(url), body: body, headers: headers);
      } else if (method == 'GET') {
        resp = await httpClient!.get(Uri.parse(url), headers: headers);
      } else if (method == 'DELETE') {
        resp = await httpClient!.delete(Uri.parse(url), headers: headers);
      } else if (method == 'HEAD') {
        resp = await httpClient!.head(Uri.parse(url), headers: headers);
      } else {
        throw OAuth2Exception('Unknown method!', errorDescription: method);
      }

      return resp;
    }

    return _supplyToken(sendRequest, httpClient: httpClient);
  }

  /// Performs the given request, adding the authorization token.
  ///
  /// If no token already exists, or if it is expired, a new one is requested.
  Future<http.StreamedResponse> send(http.BaseRequest request,
      {http.Client? httpClient}) async {
    return _send(request, httpClient: httpClient);
  }

  /// Common method for making streamed http requests
  /// Tries to use a previously fetched token, otherwise fetches a new token by means of a refresh flow or by issuing a new authorization flow
  Future<http.StreamedResponse> _send(http.BaseRequest request,
      {http.Client? httpClient}) async {
    httpClient ??= http.Client();

    sendRequest(accessToken) async {
      // Yes, it is sub-optimal that the header is changed directly like this,
      // but apparently there is no good way to clone the request object...
      request.headers['Authorization'] = 'Bearer $accessToken';
      return await httpClient!.send(request);
    }

    return _supplyToken(sendRequest, httpClient: httpClient);
  }

  /// Supplies the token to the given requester function
  Future<Response> _supplyToken<Response extends http.BaseResponse>(
      Future<Response> Function(dynamic accessToken) sendRequest,
      {http.Client? httpClient}) async {
    Response resp;

    //Retrieve the current token, or fetches a new one if it is expired
    var tknResp = await getToken(httpClient: httpClient);

    try {
      resp = await sendRequest(tknResp!.accessToken);

      if (resp.statusCode == 401) {
        //The token could have been invalidated on the server side
        //Try to fetch a new token...
        if (tknResp.hasRefreshToken()) {
          tknResp = await refreshToken(tknResp, httpClient: httpClient);
        } else {
          tknResp = await fetchToken(httpClient: httpClient);
        }

        if (tknResp.isValid()) {
          resp = await sendRequest(tknResp.accessToken);
        }
      }
    } catch (e) {
      rethrow;
    }
    return resp;
  }

  void _validateAuthorizationParams() {
    if (clientId.isEmpty) {
      throw OAuth2Exception('Required "clientId" parameter not set');
    }

    if (grantType == clientCredentials &&
        (clientSecret == null || clientSecret!.isEmpty)) {
      throw OAuth2Exception('Required "clientSecret" parameter not set');
    }
  }
}
