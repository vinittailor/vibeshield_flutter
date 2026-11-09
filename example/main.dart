import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  print('========================================================');
  print('      🛡️  VIBESHIELD FLUTTER / DART SDK DEMO  🛡️');
  print('========================================================\n');

  // Listen to non-custodial redaction events (for telemetry, Sentry, or Crashlytics)
  SecureLog.onRedacted = (event) {
    print('[Audit Hook] Secret intercepted: ${event.ruleName} -> ${event.maskedPreview}');
  };

  // 1. Known Provider Keys (Stripe, GitHub, AWS, etc.)
  print('--- 1. Known Provider Keys ---');
  SecureLog.info(
    'Configuring payment gateway',
    tag: 'PAYMENT',
    metadata: {
      'gateway': 'Stripe',
      'liveSecretKey': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // vibeshield-ignore
    },
  );

  // 2. Unknown / Proprietary Random High-Entropy Keys
  print('\n--- 2. Unknown High-Entropy Custom Token ---');
  SecureLog.warn(
    'Connecting to internal microservice',
    tag: 'AUTH',
    metadata: {
      'service': 'user-auth-service',
      'jwtSecretToken': 'aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd',
    },
  );

  // 3. Exact Environment Matches (e.g. from flutter_dotenv)
  print('\n--- 3. Exact Match from .env ---');
  SecureLog.addExactMatches(['INTERNAL_COMPANY_VAULT_PW_9981']);
  SecureLog.debug('Connecting to database with credentials: INTERNAL_COMPANY_VAULT_PW_9981');

  // 4. Convenience direct masking helper
  print('\n--- 4. Direct Masking Helpers ---');
  final rawKey = 'sk_live_51Hc29KJ8f3ks9fQ2'; // vibeshield-ignore
  print('Partial mask: ${SecureLog.mask(rawKey, overrideMode: MaskMode.partial)}');
  print('Full mask (0% overlap): ${SecureLog.mask(rawKey, overrideMode: MaskMode.full)}');

  print('\n========================================================');
  print('  ✅ All keys and metadata securely sanitized!');
  print('========================================================');
}
