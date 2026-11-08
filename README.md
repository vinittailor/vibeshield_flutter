# vibeshield_flutter

> **Flutter & Dart logging SDK for VibeShield — secret redaction with zero custody and zero production footprint via compile-time tree-shaking.**

---

## Features

- **`SecureLog.print(...)`:** Gated by `kDebugMode` (`!bool.fromEnvironment('dart.vm.product')`). During development, automatically detects and masks Stripe, AWS, GitHub, Slack, and database credentials before they reach the debug console.
- **Provable Zero Production Footprint:** In release builds (`--release`), Dart's AOT compiler evaluates `kDebugMode` to constant `false` and tree-shakes out debug logging branches completely, leaving zero binary or runtime footprint.
- **`SecureLog.mask(...)`:** Utility for single-value masking (`partial` preview or `full` shape-masking).

---

## Installation

Add to `pubspec.yaml`:

```yaml
dependencies:
  vibeshield_flutter:
    path: ../packages/flutter-sdk # or from pub.dev
```

---

## Usage

```dart
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  // Redacts credentials in debug mode; completely eliminated in release mode
  SecureLog.print('Payment key: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890');

  // Single-value masking
  final masked = SecureLog.mask('sk_live_51Hc29KJ8f3ks9fQ2', overrideMode: MaskMode.full);
  // Returns: aa_aaaa_00aa00aa0a0aa0aa0
}
```

