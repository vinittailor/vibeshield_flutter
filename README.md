# vibeshield_flutter

> **The Ultimate Flutter & Dart Secret Redaction SDK — Zero custody, zero production footprint via compile-time tree-shaking.**

---

## The Combined Approach: Complete Coverage with Zero Friction

`vibeshield_flutter` combines all 4 protection layers into one unified API:

1. **Global Zero-Friction Hook (`VibeShield.run` / `VibeShield.install`):** Wrap your app once — every standard `print()` across your entire app and third-party packages is automatically redacted.
2. **Native Dart Extensions (`secret.masked` / `text.redacted`):** Effortless, idiomatic Dart string helpers.
3. **Fluent Structured Logging (`VibeShield.log(...).data(...).send()`):** Clean structured logs with automatic recursive metadata sanitization.
4. **Network & HTTP Header Sanitizer (`VibeShield.sanitizeHeaders`):** Scrub `Authorization`, `X-Api-Key`, and bearer tokens from network logs.
5. **Shannon Entropy Engine:** Automatically detects and redacts unknown proprietary tokens even without a known provider prefix.
6. **Non-Custodial Telemetry Hook (`VibeShield.onRedacted`):** Safely forward leak detection events to Sentry or Crashlytics without leaking secrets.
7. **Provable Zero Release Footprint:** Gated by Dart's `kDebugMode` (`!bool.fromEnvironment('dart.vm.product')`). Released AOT binaries completely tree-shake out all logging logic.

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  vibeshield_flutter: ^0.1.0
```

---

## Usage

### 1. Global Zero-Friction Protection (Recommended)
Add **one line** to your `main()` function. Every single `print(...)` in your app and third-party packages is automatically sanitized!

```dart
import 'package:flutter/material.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  VibeShield.run(() => runApp(const MyApp()));
}
```

Now even regular prints are 100% safe:
```dart
print('Calling Stripe API with: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
// Terminal outputs: Calling Stripe API with: sk_live_****7890
```

---

### 2. Native Dart String Extensions
Mask secrets directly on any String:

```dart
// Partial preview: sk_live_****7890
print('Connecting with key: ${stripeKey.masked}');

// Shape-preserving full mask with 0% character overlap: aa_aaaa_00aa...
print('Secure mask: ${stripeKey.fullMasked}');

// Redact credentials out of any multiline text or JSON:
print(apiResponseJson.redacted);
```

---

### 3. Fluent Structured Logging with Metadata
Log structured data with automatic recursive sanitization:

```dart
VibeShield.log('Checkout completed', LogLevel.info)
    .tag('BILLING')
    .data({
      'userId': 1042,
      'amount': 49.99,
      'secretToken': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // Auto-sanitized!
      'customGatewayKey': 'aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd', // Auto-detected by entropy!
    })
    .send();
```

---

### 4. HTTP & Network Header Scrubbing
Sanitize network headers before logging Dio or Http requests:

```dart
final headers = {
  'Authorization': 'Bearer sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890',
  'X-Api-Key': 'AKIAIOSFODNN7EXAMPLE',
  'Content-Type': 'application/json',
};

final safeHeaders = VibeShield.sanitizeHeaders(headers);
// Output: {Authorization: Bearer sk_live_****7890, X-Api-Key: AKIA****MPLE, Content-Type: application/json}
```

---

### 5. Non-Custodial Telemetry Hook (Sentry / Crashlytics)
Receive notifications when credentials are intercepted without storing or sending the raw secret:

```dart
VibeShield.onRedacted = (RedactionEvent event) {
  // Safe to pipe to Crashlytics or Sentry:
  // event.ruleName      -> "Stripe Live Secret Key"
  // event.category      -> "payment"
  // event.maskedPreview -> "sk_live_****7890"  (ZERO raw secrets)
  // event.timestamp     -> 2026-11-09 ...
  print('[Audit] Blocked leak of ${event.ruleName}');
};
```

---

### 6. Backward Compatibility
Existing code using `SecureLog.print(...)` or `SecureLog.mask(...)` works with zero changes:
```dart
SecureLog.print('Payment key: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
```
