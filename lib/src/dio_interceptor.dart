import 'package:dio/dio.dart';
import 'vibeshield.dart';
import 'secure_log.dart' show kDebugMode;

/// Plug-and-play Dio interceptor that automatically scrubs sensitive credentials
/// from HTTP request headers, query parameters, request bodies, and responses.
///
/// Usage:
/// ```dart
/// final dio = Dio();
/// dio.interceptors.add(VibeShieldDioInterceptor());
/// ```
class VibeShieldDioInterceptor extends Interceptor {
  final MaskMode? overrideMode;
  final bool logRequests;
  final bool logResponses;
  final bool logErrors;

  VibeShieldDioInterceptor({
    this.overrideMode,
    this.logRequests = true,
    this.logResponses = true,
    this.logErrors = true,
  });

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // 1. Sanitize request headers
    options.headers = VibeShield.sanitizeHeaders(options.headers, overrideMode: overrideMode);

    // 2. Sanitize query parameters
    if (options.queryParameters.isNotEmpty) {
      options.queryParameters = Map<String, dynamic>.from(
        VibeShield.sanitize(options.queryParameters, overrideMode: overrideMode) as Map,
      );
    }

    // 3. Sanitize request payload
    if (options.data != null) {
      options.data = VibeShield.sanitize(options.data, overrideMode: overrideMode);
    }

    if (kDebugMode && logRequests) {
      VibeShield.print(
        '--> ${options.method} ${options.uri}',
        tag: 'DIO-REQ',
        metadata: {
          'headers': options.headers,
          if (options.queryParameters.isNotEmpty) 'query': options.queryParameters,
          if (options.data != null) 'body': options.data,
        },
      );
    }

    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    // Sanitize response body
    if (response.data != null) {
      response.data = VibeShield.sanitize(response.data, overrideMode: overrideMode);
    }

    if (kDebugMode && logResponses) {
      VibeShield.print(
        '<-- ${response.statusCode} ${response.requestOptions.uri}',
        tag: 'DIO-RES',
        metadata: {
          'status': response.statusCode,
          if (response.data != null) 'data': response.data,
        },
      );
    }

    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (kDebugMode && logErrors) {
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

