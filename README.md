# vibeshield_flutter

> **Flutter & Dart logging SDK for VibeShield — secret redaction with zero custody and zero production footprint via compile-time tree-shaking.**

---

## Features

- **`SecureLog.print(...)` / `info` / `warn` / `error` / `debug`:** Gated by `kDebugMode` (`!bool.fromEnvironment('dart.vm.product')`). During development, automatically detects and masks Stripe, AWS, GitHub, Slack, database credentials, and unknown high-entropy keys before they reach the debug console.
- **Recursive Metadata Sanitization:** Pass structured `metadata: {'token': 'sk_live_...', 'user': 123}` maps or lists — all nested values are automatically sanitized.
- **Shannon Entropy Heuristics:** Automatically detects and redacts unknown, random proprietary tokens even without a known provider prefix.
- **`onRedacted` Audit Callback:** Non-custodial hook fired when secrets are redacted (for reporting to Sentry, Crashlytics, or telemetry without sending raw secrets).
- **Provable Zero Production Footprint:** In release builds (`--release`), Dart's AOT compiler evaluates `kDebugMode` to constant `false` and tree-shakes out debug logging branches completely, leaving zero binary or runtime footprint.
- **`SecureLog.mask(...)`:** Utility for single-value masking (`partial` preview or `full` shape-masking).

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  vibeshield_flutter: ^0.1.0
```

---

## Usage

### 1. Basic Logging
```dart
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  // Redacts credentials in debug mode; completely eliminated in release mode
  SecureLog.print('Payment key: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');
}
```

### 2. Structured Logging with Metadata
```dart
SecureLog.info(
  'User checkout started',
  tag: 'PAYMENT',
  metadata: {
    'userId': 42,
    'gateway': 'Stripe',
    'authToken': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // Auto-masked!
  },
);
```

### 3. Non-Custodial Telemetry Hook
```dart
SecureLog.onRedacted = (event) {
  // Reports to Crashlytics/Sentry that a secret was blocked (no raw secret stored)
  print('Blocked leak: ${event.ruleName} -> ${event.maskedPreview}');
};
```

### 4. Single-Value Masking
```dart
final masked = SecureLog.mask('sk_live_51Hc29KJ8f3ks9fQ2', overrideMode: MaskMode.full);
// Returns: aa_aaaa_00aa00aa0a0aa0aa0 (Guaranteed 0% character overlap)
```

