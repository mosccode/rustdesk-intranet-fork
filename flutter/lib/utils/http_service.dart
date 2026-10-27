import 'dart:convert';
import 'package:http/http.dart' as http;
export 'package:http/http.dart' show Response;

enum HttpMethod { get, post, put, delete }

class HttpService {
  /// netguard L3 (需求 §二.1): every Dart-side HTTP request is refused here, before any client is
  /// built. Upstream picked at runtime between a pure-Dart `http.Client()` and the Rust stack
  /// (`useFlutterHttp`); both paths are gone from this build - the Rust entry is a refusal stub and
  /// the cloud features it served (account login, address book) are deleted. Returning an explicit
  /// error keeps the ~27 call sites compiling and tells the caller why nothing happened.
  ///
  /// `package:http` is still imported for its `Response` type only; no `Client` is constructed here
  /// or anywhere else in this app.
  Future<http.Response> sendRequest(
    Uri url,
    HttpMethod method, {
    Map<String, String>? headers,
    dynamic body,
  }) async {
    return http.Response(
      '{"error": "Network requests are removed from this build (netguard L3)."}',
      400,
      headers: {'content-type': 'application/json'},
    );
  }
}

Future<http.Response> get(Uri url, {Map<String, String>? headers}) async {
  return await HttpService().sendRequest(url, HttpMethod.get, headers: headers);
}

Future<http.Response> post(Uri url,
    {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
  return await HttpService()
      .sendRequest(url, HttpMethod.post, body: body, headers: headers);
}

Future<http.Response> put(Uri url,
    {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
  return await HttpService()
      .sendRequest(url, HttpMethod.put, body: body, headers: headers);
}

Future<http.Response> delete(Uri url,
    {Map<String, String>? headers, Object? body, Encoding? encoding}) async {
  return await HttpService()
      .sendRequest(url, HttpMethod.delete, body: body, headers: headers);
}
