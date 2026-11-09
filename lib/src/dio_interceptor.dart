import 'package:dio/dio.dart';
import 'vibeshield.dart';

/// Plug-and-play Dio interceptor that automatically scrubs sensitive credentials
/// from HTTP request headers, query parameters, request bodies, and responses in logs.
///
/// In release builds (`--release`), if [enableInRelease] is false (the default),
/// this interceptor immediately bypasses with zero overhead to protect production performance.
///
/// Usage:
/// ```dart
/// final dio = Dio();
/// dio.interceptors.add(VibeShieldDioInterceptor());
/// ```
class VibeShieldDioInterceptor extends Interceptor {
  /// Explicit masking mode for this interceptor.
  /// When null, defaults to the globally active [VibeShield.maskMode].
  final MaskMode? overrideMode;

  /// Whether to run this interceptor in release builds (`--release`).
  /// Defaults to `false` so the interceptor immediately calls `handler.next()` with zero overhead in production.
  final bool enableInRelease;

  /// Whether to log outgoing HTTP requests (method, URI, sanitized headers, query params, and body).
  final bool logRequests;

  /// Whether to log incoming HTTP responses (status code, URI, and sanitized response body).
  final bool logResponses;

  /// Whether to log Dio HTTP errors and stack traces with sanitized output.
  final bool logErrors;

  /// Creates a new [VibeShieldDioInterceptor] with configurable logging options.
  ///
  /// * [overrideMode]: Optional mode override ([MaskMode.partial], [MaskMode.full], or [MaskMode.off]).
  /// * [enableInRelease]: Set to true only if you explicitly want network logs in production. Default is `false`.
  /// * [logRequests]: Enable/disable logging outgoing requests. Default is `true`.
  /// * [logResponses]: Enable/disable logging incoming responses. Default is `true`.
  /// * [logErrors]: Enable/disable logging Dio exceptions. Default is `true`.
  VibeShieldDioInterceptor({
    this.overrideMode,
    this.enableInRelease = false,
    this.logRequests = true,
    this.logResponses = true,
    this.logErrors = true,
  });

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // In production release builds, bypass completely if enableInRelease is false
    if (!kDebugMode && !enableInRelease) {
      handler.next(options);
      return;
    }

    if (logRequests) {
      // Sanitize a copy of headers, queries, and payload for logging
      // without corrupting the real network request sent over the wire!
      final safeHeaders = VibeShield.sanitizeHeaders(options.headers, overrideMode: overrideMode);
      final safeQuery = options.queryParameters.isNotEmpty
          ? VibeShield.sanitize(options.queryParameters, overrideMode: overrideMode)
          : null;
      final safeData = options.data != null
          ? VibeShield.sanitize(options.data, overrideMode: overrideMode)
          : null;

      VibeShield.print(
        '--> ${options.method} ${options.uri}',
        tag: 'DIO-REQ',
        metadata: {
          'headers': safeHeaders,
          if (safeQuery != null) 'query': safeQuery,
          if (safeData != null) 'body': safeData,
        },
      );
    }

    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (!kDebugMode && !enableInRelease) {
      handler.next(response);
      return;
    }

    if (logResponses) {
      final safeData = response.data != null
          ? VibeShield.sanitize(response.data, overrideMode: overrideMode)
          : null;

      VibeShield.print(
        '<-- ${response.statusCode} ${response.requestOptions.uri}',
        tag: 'DIO-RES',
        metadata: {
          'status': response.statusCode,
          if (safeData != null) 'data': safeData,
        },
      );
    }

    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (!kDebugMode && !enableInRelease) {
      handler.next(err);
      return;
    }

    if (logErrors) {
      VibeShield.error(
        '<-- ERROR ${err.requestOptions.uri}: ${err.message}',
        tag: 'DIO-ERR',
        error: err.error,
        stackTrace: err.stackTrace,
      );
    }

    handler.next(err);
  }
}
