import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  print('========================================================');
  print('    🛡️  UNIFIED VIBESHIELD FLUTTER / DART SDK DEMO  🛡️');
  print('========================================================\n');

  // Hook for Sentry, Firebase Crashlytics, or internal telemetry (Zero raw custody)
  VibeShield.onRedacted = (event) {
    print('  [Audit Hook] Intercepted: ${event.ruleName} -> ${event.maskedPreview}');
  };

  // ----------------------------------------------------------------------
  // 1. Better Way #1: Zero-Friction Global Interception (VibeShield.run)
  // ----------------------------------------------------------------------
  print('--- 1. Zero-Friction Global Interception (VibeShield.run) ---');
  VibeShield.run(() {
    // Normal print() calls anywhere in your app or third-party packages:
    print('Calling Stripe API with: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore
    print('AWS access key: AKIAIOSFODNN7EXAMPLE'); // vibeshield-ignore
  });

  // ----------------------------------------------------------------------
  // 2. Better Way #2: Native Dart Extension Methods (secret.masked)
  // ----------------------------------------------------------------------
  print('\n--- 2. Native Dart String Extensions (.masked / .redacted) ---');
  const userToken = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'; // vibeshield-ignore
  print('Single value preview:  ${userToken.masked}');
  print('Full zero-overlap mask: ${userToken.fullMasked}');

  const multilineLog = 'Server log: user logged in, token is ghp_16C7e42F292c6912E7710c838347Ae178B4a'; // vibeshield-ignore
  print('Redacted full text:    ${multilineLog.redacted}');

  // ----------------------------------------------------------------------
  // 3. Better Way #3: Fluent Structured Logging with Metadata
  // ----------------------------------------------------------------------
  print('\n--- 3. Fluent Structured Logging with Auto-Sanitized Data ---');
  VibeShield.log('User completed in-app checkout', LogLevel.info)
      .tag('CHECKOUT')
      .data({
        'userId': 1042,
        'amount': 49.99,
        'stripeSecret': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // Auto-redacted! // vibeshield-ignore
        'nested': {
          'proprietaryHighEntropyToken': 'aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd', // Auto-detected by entropy!
        },
      })
      .send();

  // ----------------------------------------------------------------------
  // 4. Better Way #4: HTTP & Network Header Scrubbing
  // ----------------------------------------------------------------------
  print('\n--- 4. HTTP & Network Header Scrubbing ---');
  final networkHeaders = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // vibeshield-ignore
    'X-Api-Key': 'AKIAIOSFODNN7EXAMPLE', // vibeshield-ignore
    'User-Agent': 'FlutterApp/1.0',
  };
  final safeHeaders = VibeShield.sanitizeHeaders(networkHeaders);
  print('Safe Network Headers: $safeHeaders');

  print('\n========================================================');
  print('  ✅ All approaches unified seamlessly in one package!');
  print('========================================================');
}
