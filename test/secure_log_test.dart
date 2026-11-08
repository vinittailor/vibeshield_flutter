import 'package:test/test.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  group('Dart/Flutter SecureLog Unit Tests', () {
    setUp(() {
      SecureLog.mode = MaskMode.partial;
      SecureLog.customPrinter = null;
    });

    test('SecureLog.mask in partial mode', () {
      final secret = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890';
      final masked = SecureLog.mask(secret, overrideMode: MaskMode.partial);
      expect(masked.startsWith('sk_live_****'), isTrue);
      expect(masked.endsWith('7890'), isTrue);
      expect(masked.contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
    });

    test('SecureLog.mask in full mode guarantees zero character overlap', () {
      final secret = 'sk_live_51Hc29KJ8f3ks9fQ2';
      final masked = SecureLog.mask(secret, overrideMode: MaskMode.full);
      expect(masked, equals('aa_aaaa_00aa00aa0a0aa0aa0'));
      expect(verifyZeroCharacterOverlap(secret, masked), isTrue);
    });

    test('SecureLog.redact removes live secrets from log messages', () {
      final log = 'Payment key: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890 for AWS AKIAIOSFODNN7EXAMPLE';
      final redacted = SecureLog.redact(log);

      expect(redacted.contains('sk_live_****7890'), isTrue);
      expect(redacted.contains('AKIA****MPLE'), isTrue);
      expect(redacted.contains('51Hc29KJ8f3ks9fQ2ABCDEF12'), isFalse);
      expect(redacted.contains('IOSFODNN7EXA'), isFalse);
    });

    test('SecureLog.print intercepts and outputs redacted logs in debug mode', () {
      final captured = <String>[];
      SecureLog.customPrinter = (msg) => captured.add(msg);

      SecureLog.print('Connecting to https://ghp_16C7e42F292c6912E7710c838347Ae178B4a@github.com');

      expect(captured.length, equals(1));
      expect(captured[0].contains('ghp_****8B4a'), isTrue);
      expect(captured[0].contains('16C7e42F292c6912E7710c838347Ae17'), isFalse);
    });

    test('exactMatches redaction', () {
      SecureLog.addExactMatches(['CUSTOM_TOP_SECRET_AUTH_TOKEN']);
      final log = 'Auth: Bearer CUSTOM_TOP_SECRET_AUTH_TOKEN';
      final redacted = SecureLog.redact(log);

      expect(redacted.contains('CUSTOM_TOP_SECRET_AUTH_TOKEN'), isFalse);
    });
  });
}

