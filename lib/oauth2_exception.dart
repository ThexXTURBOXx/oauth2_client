class OAuth2Exception implements Exception {
  String error;
  String? errorDescription;

  OAuth2Exception(this.error, {this.errorDescription});

  @override
  String toString() {
    var str = 'OAuth2Exception: $error';
    if (errorDescription != null) str += ' ($errorDescription)';
    return str;
  }
}
