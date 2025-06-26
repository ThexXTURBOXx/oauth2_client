import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';

import 'base_web_auth.dart';

BaseWebAuth createWebAuth() => FlutterWebAuth2Authenticator();

class FlutterWebAuth2Authenticator implements BaseWebAuth {
  @override
  Future<String> authenticate(
      {required String callbackUrlScheme,
      required String url,
      required String redirectUrl,
      Map<String, dynamic>? opts}) async {
    return await FlutterWebAuth2.authenticate(
      callbackUrlScheme: callbackUrlScheme,
      url: url,
      options: FlutterWebAuth2Options.fromJson(opts ?? {}),
    );
  }
}
