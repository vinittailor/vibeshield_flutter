import 'package:dio/dio.dart';
import 'vibeshield.dart';
import 'secure_log.dart' show kDebugMode;

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
  final MaskMode? overrideMode;
  final bool enableInRelease;
  final bool logRequests;
  final bool logResponses;
  final bool logErrors;

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
