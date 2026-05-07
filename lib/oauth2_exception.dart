class OAuth2Exception implements Exception {
  String error;
  String? errorDescription;
  Exception? cause;
  StackTrace? causeTrace;

  OAuth2Exception(this.error,
      {this.errorDescription, this.cause, this.causeTrace});

  @override
  String toString() {
    var str = 'OAuth2Exception: $error';
    if (errorDescription != null) str += ' ($errorDescription)';
    if (cause != null) str += ' caused by: ($cause)';
    return str;
  }
}
