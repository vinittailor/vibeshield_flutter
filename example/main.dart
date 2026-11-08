import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  print('--- VibeShield Flutter/Dart SDK Demo ---');

  // 1. Live debug redaction
  // When running in debug mode (kDebugMode), secrets are automatically redacted
  SecureLog.print('Configuring Stripe API with live secret key:');
  SecureLog.print('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore

  // 2. Convenience single-value masking helper
  final rawKey = 'sk_live_51Hc29KJ8f3ks9fQ2'; // vibeshield-ignore
  print('Partial preview: ${SecureLog.mask(rawKey, overrideMode: MaskMode.partial)}');
  print('Full shape mask: ${SecureLog.mask(rawKey, overrideMode: MaskMode.full)}');

  // 3. Zero production footprint
  // In release builds (`dart.vm.product == true`), `kDebugMode` evaluates to false at compile time,
  // causing Dart's AOT compiler to tree-shake out all logging logic completely.
}
