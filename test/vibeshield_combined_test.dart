import 'package:test/test.dart';
import 'package:dio/dio.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  group('Unified VibeShield Combined Approach Tests', () {
    test('1. Extension Methods on String (apiKey.masked, .fullMasked, .redacted)', () {
      const stripeKey = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
      expect(stripeKey.masked.startsWith('sk_live_****'), isTrue);
      expect(stripeKey.masked.endsWith('7890'), isTrue);

      const secret = 'sk_live_51Hc29KJ8f3ks9fQ2';
      final fullMask = secret.fullMasked;
      expect(fullMask, equals('aa_aaaa_00aa00aa0a0aa0aa0'));
      expect(verifyZeroCharacterOverlap(secret, fullMask), isTrue);

      const logMessage = 'Connecting to Stripe sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890 securely';
      expect(logMessage.redacted.contains('sk_live_****7890'), isTrue);
      expect(logMessage.redacted.contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
    });

    test('2. Global Zone Interception (VibeShield.run)', () {
      final captured = <String>[];
      VibeShield.customPrinter = (msg) => captured.add(msg);

      VibeShield.run(() {
        // Standard print with zero VibeShield references inside the block:
        print('Raw log with key: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
      });

      expect(captured.length, equals(1));
      expect(captured[0].contains('sk_live_****7890'), isTrue);
      expect(captured[0].contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      VibeShield.customPrinter = null;
    });

    test('3. Fluent Structured Logging with Metadata (.data().tag().send())', () {
      final captured = <String>[];
      VibeShield.customPrinter = (msg) => captured.add(msg);

      VibeShield.log('User completed checkout', LogLevel.info)
          .tag('BILLING')
          .data({
            'userId': 99,
            'stripeKey': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
            'nested': {
              'apiKey': 'AKIAIOSFODNN7EXAMPLE',
            },
          })
          .send();

      expect(captured.length, equals(1));
      final out = captured[0];
      expect(out.contains('[BILLING] User completed checkout'), isTrue);
      expect(out.contains('sk_live_****7890'), isTrue);
      expect(out.contains('AKIA****MPLE'), isTrue);
      expect(out.contains('51Hc29KJ8f3ks9fQ2'), isFalse);
      expect(out.contains('IOSFODNN7EXA'), isFalse);
      VibeShield.customPrinter = null;
    });

    test('4. HTTP & Network Header Scrubbing (VibeShield.sanitizeHeaders)', () {
      final headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
        'X-Api-Key': 'AKIAIOSFODNN7EXAMPLE',
        'User-Agent': 'FlutterApp/1.0',
      };

      final sanitized = VibeShield.sanitizeHeaders(headers);

      expect(sanitized['Content-Type'], equals('application/json'));
      expect(sanitized['User-Agent'], equals('FlutterApp/1.0'));
      expect(sanitized['Authorization'].toString().contains('sk_live_****7890'), isTrue);
      expect(sanitized['Authorization'].toString().contains('51Hc29KJ8f3ks9fQ2'), isFalse);
      expect(sanitized['X-Api-Key'].toString().contains('AKIA****MPLE'), isTrue);
      expect(sanitized['X-Api-Key'].toString().contains('IOSFODNN7EXA'), isFalse);
    });

    test('5. Backward Compatibility: SecureLog alias works identical to VibeShield', () {
      expect(SecureLog.mask('sk_live_51Hc29KJ8f3ks9fQ2'), equals('sk_live_****9fQ2'));
    });

    test('6. Three Masking Modes: Off, Half (Partial), and Full + cycleMode', () {
      const secret = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';

      // Mode: OFF
      VibeShield.setMode(MaskMode.off);
      expect(VibeShield.isOff, isTrue);
      expect(VibeShield.redact('Key: $secret'), equals('Key: $secret'));

      // Mode: HALF / PARTIAL
      VibeShield.setMode(MaskMode.partial);
      expect(VibeShield.isPartial, isTrue);
      expect(VibeShield.redact('Key: $secret'), contains('sk_live_****7890'));
      expect(secret.halfMasked, contains('sk_live_****7890'));

      // Mode: FULL (Shape-preserving, 0% overlap)
      VibeShield.setMode(MaskMode.full);
      expect(VibeShield.isFull, isTrue);
      final full = VibeShield.redact('Key: $secret');
      expect(full.contains('sk_live'), isFalse);
      expect(full.contains('aa_aaaa'), isTrue);

      // cycleMode: full -> off -> partial -> full
      expect(VibeShield.cycleMode(), equals(MaskMode.off));
      expect(VibeShield.cycleMode(), equals(MaskMode.partial));
      expect(VibeShield.cycleMode(), equals(MaskMode.full));

      // Reset
      VibeShield.setMode(MaskMode.partial);
    });

    test('7. Direct VibeShieldDioInterceptor cleans headers, query, and body in logs', () {
      final captured = <String>[];
      VibeShield.customPrinter = (msg) => captured.add(msg);

      final dio = Dio();
      final interceptor = VibeShield.dioInterceptor();
      dio.interceptors.add(interceptor);
      expect(dio.interceptors.contains(interceptor), isTrue);

      final options = RequestOptions(
        path: '/v1/charges',
        headers: {
          'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
        },
        queryParameters: {
          'apiKey': 'AKIAIOSFODNN7EXAMPLE',
        },
        data: {
          'clientSecret': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
          'amount': 2000,
        },
      );

      final handler = _TestRequestHandler();
      interceptor.onRequest(options, handler);

      expect(handler.passedOptions, isNotNull);
      // The real HTTP request over the wire preserves the valid authorization key
      expect(options.headers['Authorization'], equals('Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'));

      // BUT the logged console output has the secret safely redacted!
      expect(captured.isNotEmpty, isTrue);
      final log = captured[0];
      expect(log.contains('sk_live_****7890'), isTrue);
      expect(log.contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      expect(log.contains('AKIA****MPLE'), isTrue);

      VibeShield.customPrinter = null;
    });

    test('8. Provable Zero Release Footprint: enableInRelease = false directly runs body', () {
      bool executed = false;
      final value = VibeShield.run(
        () {
          executed = true;
          return 'hello_production';
        },
        enableInRelease: false,
      );

      expect(executed, isTrue);
      expect(value, equals('hello_production'));
    });

    test('9. SecureKey AI-Proof Wrapper: prevents toString/JSON/context leakage', () {
      const rawSecret = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
      const secureKey = SecureKey(rawSecret);

      // String interpolation & toString ONLY returns masked preview
      expect(secureKey.toString(), contains('sk_live_****7890'));
      expect(secureKey.toString().contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      expect('Bearer $secureKey', contains('sk_live_****7890'));

      // JSON serialization is safe
      expect(secureKey.toJson().toString(), contains('sk_live_****7890'));

      // Raw value is ONLY accessible via explicit exposeRaw()
      expect(secureKey.exposeRaw(), equals(rawSecret));
    });

    test('10. VibeShield.aiSafe & String.aiSafe scrubs prompts before sending to LLMs', () {
      const promptWithSecret =
          'User asked for refund on Stripe key sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890 and token ghp_16C7e42F292c6912E7710c838347Ae178B4a';

      final safePrompt = promptWithSecret.aiSafe;
      expect(safePrompt.contains('sk_live'), isFalse);
      expect(safePrompt.contains('ghp_'), isFalse);
      expect(safePrompt.contains('51Hc29KJ8f3ks9fQ2'), isFalse);

      final safeMap = VibeShield.aiSafe({
        'context': 'Debug context',
        'auth': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
      }) as Map;

      expect(safeMap['auth'].toString().contains('sk_live'), isFalse);
    });
  });
}

class _TestRequestHandler extends RequestInterceptorHandler {
  RequestOptions? passedOptions;

  @override
  void next(RequestOptions requestOptions) {
    passedOptions = requestOptions;
  }
}
