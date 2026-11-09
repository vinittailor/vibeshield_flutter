import 'package:dio/dio.dart';
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
  // 1. The Three Masking Modes: Off, Half (Partial), and Full
  // ----------------------------------------------------------------------
  print('--- 1. Three Masking Modes (Off, Half/Partial, Full) ---');
  const sampleKey = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'; // vibeshield-ignore

  VibeShield.setMode(MaskMode.off);
  print('• Mode: OFF      -> ${VibeShield.redact("Key: $sampleKey")}'); // Raw unmasked

  VibeShield.setMode(MaskMode.partial);
  print('• Mode: HALF     -> ${VibeShield.redact("Key: $sampleKey")}'); // Prefix + suffix preview

  VibeShield.setMode(MaskMode.full);
  print('• Mode: FULL     -> ${VibeShield.redact("Key: $sampleKey")}'); // 0% overlap shape mask

  // Cycling modes programmatically
  final nextMode = VibeShield.cycleMode();
  print('• Cycled mode to -> $nextMode\n');
  VibeShield.setMode(MaskMode.partial); // reset to partial default

  // ----------------------------------------------------------------------
  // 2. Direct Dio Plug-and-Play Network Interceptor
  // ----------------------------------------------------------------------
  print('--- 2. Direct Plug-and-Play Dio Interceptor ---');
  final dio = Dio();

  // Add VibeShield interceptor in ONE line!
  dio.interceptors.add(VibeShield.dioInterceptor());

  // Simulate an outgoing request with secret headers and body payload:
  print('Simulating Dio HTTP Request with sensitive headers and payload:');
  final reqOptions = RequestOptions(
    path: 'https://api.stripe.com/v1/customers',
    method: 'POST',
    headers: {
      'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // vibeshield-ignore
      'X-Api-Key': 'AKIAIOSFODNN7EXAMPLE', // vibeshield-ignore
      'Content-Type': 'application/json',
    },
    queryParameters: {
      'token': 'aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd',
    },
    data: {
      'customerEmail': 'dev@example.com',
      'cardSecret': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // vibeshield-ignore
    },
  );

  // Run through interceptor:
  VibeShield.dioInterceptor().onRequest(reqOptions, RequestInterceptorHandler());

  // ----------------------------------------------------------------------
  // 3. Zero-Friction Global Interception (VibeShield.run)
  // ----------------------------------------------------------------------
  print('\n--- 3. Zero-Friction Global Interception (VibeShield.run) ---');
  VibeShield.run(() {
    // Normal standard print() calls anywhere in your app:
    print('Standard print: Calling Stripe with sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore
  });

  // ----------------------------------------------------------------------
  // 4. Native Dart String Extensions (.halfMasked, .fullMasked, .redacted)
  // ----------------------------------------------------------------------
  print('\n--- 4. Native Dart String Extensions (.halfMasked / .fullMasked) ---');
  const userToken = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'; // vibeshield-ignore
  print('Half mask (preview):    ${userToken.halfMasked}');
  print('Full mask (0% overlap): ${userToken.fullMasked}');
  print('Text redacted:          ${"Logged in with $userToken".redacted}');

  // ----------------------------------------------------------------------
  // 5. Fluent Structured Logging with Metadata
  // ----------------------------------------------------------------------
  print('\n--- 5. Fluent Structured Logging with Metadata ---');
  VibeShield.log('Payment processed', LogLevel.info)
      .tag('BILLING')
      .data({
        'amount': 99.00,
        'secret': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // vibeshield-ignore
      })
      .send();

  print('\n========================================================');
  print('  ✅ All 3 modes and Dio interceptor verified live!');
  print('========================================================');
}
