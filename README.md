# vibeshield_flutter

[![Pub Version](https://img.shields.io/pub/v/vibeshield_flutter.svg)](https://pub.dev/packages/vibeshield_flutter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dart SDK](https://img.shields.io/badge/Dart-3.0+-blue.svg)](https://dart.dev)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/vinittailor/vibeshield_flutter)

> **The Ultimate Flutter & Dart Secret Redaction SDK — Zero custody, zero production footprint, and airtight protection against leaks to logs, AI assistants, and network traces.**

---

## Why VibeShield Flutter?

Every Flutter developer accidentally prints credentials during debugging: Stripe keys, AWS tokens, Firebase auth tokens, or database URLs. These strings immediately leak into:
1. **Terminal & IDE Logs:** Visible to anyone watching your screen or recorded in CI logs ([CWE-532](https://cwe.mitre.org/data/definitions/532.html)).
2. **AI Assistants:** Tools like Cursor, GitHub Copilot, and Claude Code read your terminal and editor context, uploading raw keys to LLM servers.
3. **Crash & Telemetry Services:** Sentry or Firebase Crashlytics capture breadcrumbs with unredacted API tokens.
4. **Network Interceptors:** Dio logger interceptors print `Authorization: Bearer <secret>` in plain text.

`vibeshield_flutter` solves all of this with **zero code friction**, **provable zero release overhead**, and **zero custody**.

---

## Core Pillars

- ⚡ **Zero Production Footprint:** In release builds (`flutter build apk --release` / `flutter build appbundle`), Dart's AOT compiler evaluates `kDebugMode` to compile-time `false`. `VibeShield.run()` directly runs your app with **zero Dart Zones, zero print hooks, and 0% performance overhead**.
- 🔒 **Zero Custody:** Raw secrets are **never** persisted to disk, stored in memory buffers, or transmitted externally.
- 🤖 **AI-Proof Architecture:** Provides `SecureKey`, `prompt.aiSafe`, and automated `.cursorignore` / `.copilotignore` generators so AI tools never see real credentials.
- 🌐 **Network Wire Safe:** The Dio interceptor sanitizes console logs while preserving 100% valid credentials on the actual HTTP network wire.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Masking Modes](#masking-modes)
- [Production Release Bypass](#production-release-bypass)
- [Dio Network Interceptor](#dio-network-interceptor)
- [AI Leak Protection](#ai-leak-protection)
  - [1. SecureKey AI-Proof Wrapper](#1-securekey-ai-proof-wrapper)
  - [2. AI Prompt Sanitization](#2-ai-prompt-sanitization)
  - [3. Project AI Shield](#3-project-ai-shield)
- [Static Security CLI Scanner](#static-security-cli-scanner)
- [Native Dart String Extensions](#native-dart-string-extensions)
- [Fluent Structured Logging](#fluent-structured-logging)
- [Crashlytics & Sentry Telemetry Hook](#crashlytics--sentry-telemetry-hook)
- [Supported Secret Rules](#supported-secret-rules)
- [Backward Compatibility](#backward-compatibility)
- [License](#license)

---

## Quick Start

### 1. Add Dependency

```yaml
dependencies:
  vibeshield_flutter: ^0.1.0
```

### 2. Wrap `runApp()` in `main()`

Add **one line** to your `main()` function:

```dart
import 'package:flutter/material.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

void main() {
  VibeShield.run(() => runApp(const MyApp()));
}
```

Now every standard `print(...)` across your entire application and 3rd-party dependencies is automatically redacted in your debug console:

```dart
// Your regular print statement:
print('Calling Stripe API with: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore

// What appears in your IDE terminal:
// Calling Stripe API with: sk_live_****7890
```

---

## Masking Modes

VibeShield provides 3 distinct masking modes:

| Mode | Visual Representation | Use Case |
| :--- | :--- | :--- |
| `MaskMode.partial` (Default) | `sk_live_****7890` | Identifies provider prefix while concealing secret payload. |
| `MaskMode.full` | `aa_aaaa_00aa00AA...` | Shape-preserving full mask with **0% character overlap guarantee**. Ideal for live streams and AI prompts. |
| `MaskMode.off` | `sk_live_51Hc29...` | Raw pass-through for isolated, controlled local debugging. |

### Setting or Cycling Modes

```dart
// Set globally at startup
VibeShield.run(
  () => runApp(const MyApp()),
  mode: MaskMode.full,
);

// Or change dynamically at runtime
VibeShield.maskMode = MaskMode.full;

// Cycle through: off -> partial -> full -> off
final newMode = VibeShield.cycleMode();
```

---

## Production Release Bypass

To guarantee that your production release builds (`APK`, `AAB`, `iOS IPA`, `Web`) have **zero risk of crashes, zero latency, and zero memory overhead**, VibeShield includes `enableInRelease: false` (default):

```dart
void main() {
  VibeShield.run(
    () => runApp(const MyApp()),
    enableInRelease: false, // Default: completely bypassed in release builds
  );
}
```

### How it works:
- In **Debug Mode** (`kDebugMode == true`), VibeShield runs inside a Dart Zone to intercept and scrub logs.
- In **Release Mode** (`kDebugMode == false`), Dart's AOT compiler optimizes away the check and immediately executes `body()` directly. **Zero Dart Zones are spawned.**

---

## Dio Network Interceptor

When using [Dio](https://pub.dev/packages/dio), logging interceptors often expose raw `Authorization` headers and JSON request bodies in your terminal.

`VibeShieldDioInterceptor` sanitizes the logged output while **keeping the actual HTTP request untouched over the network wire**:

```dart
import 'package:dio/dio.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

final dio = Dio();

// Add VibeShield interceptor
dio.interceptors.add(VibeShield.dioInterceptor());

// Or with custom options
dio.interceptors.add(VibeShieldDioInterceptor(
  logHeaders: true,
  logBody: true,
  enableInRelease: false, // Automatically disabled in release
));
```

### What happens:
```text
--> POST https://api.stripe.com/v1/charges
Headers: {Authorization: Bearer sk_live_****7890}
Body: {"clientSecret": "sk_live_****7890", "amount": 2000}
```
*Live Stripe servers still receive the genuine `Authorization: Bearer sk_live_51Hc29...` token, so payments never fail!*

---

## AI Leak Protection

Modern AI developer tools (Cursor, Copilot, Claude Code) read code files, variables, and terminal outputs, unintentionally sending sensitive credentials to LLM cloud providers. VibeShield gives you 3 layers of defense:

### 1. `SecureKey` AI-Proof Wrapper

Wrap your keys in Dart code:

```dart
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

// Wrap your sensitive key
final stripeKey = SecureKey('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore
```

- **Safe String Interpolation:** `print('Config: $stripeKey');` prints only `Config: sk_live_****7890`. AI context scrapers cannot read the raw secret.
- **Safe JSON Serialization:** `jsonEncode({'key': stripeKey});` yields `{"key": "sk_live_****7890"}`.
- **Only Expose During HTTPS Handshake:**
  ```dart
  // When making the actual API call:
  dio.options.headers['Authorization'] = 'Bearer ${stripeKey.exposeRaw()}';
  ```

### 2. AI Prompt Sanitization

If your app feeds user queries, debug logs, or error traces to LLMs (OpenAI, Gemini, Anthropic), scrub them with `aiSafe`:

```dart
final rawContext = 'Error with token: ghp_16C7e42F292c6912E7710c838347Ae178B4a'; // vibeshield-ignore

// Shape-preserving zero-overlap mask
final safePrompt = rawContext.aiSafe;

// Safe to send to Gemini or OpenAI:
await geminiClient.prompt(safePrompt);
```

You can also sanitize structured maps:
```dart
final safeData = VibeShield.aiSafe(debugStateMap);
```

### 3. Project AI Shield

Run this command from your terminal to generate AI-exclusion files:

```bash
dart run vibeshield --shield-ai
```

This automatically creates and synchronizes:
- `.cursorignore` (Cursor AI)
- `.copilotignore` (GitHub Copilot)
- `.claudeignore` (Claude Code)
- `.aiexclude` (JetBrains AI)

It shields:
- `.env*`
- `android/key.properties`
- `android/app/google-services.json`
- `ios/Runner/GoogleService-Info.plist`
- `*.keystore`, `*.jks`, `*.pem`, `*.p12`

---

## Static Security CLI Scanner

VibeShield includes an offline static code scanner to detect hardcoded secrets before you deploy:

```bash
# Scan current project
dart run vibeshield

# Scan specific directory
dart run vibeshield --path=lib

# Output JSON for CI/CD pipelines
dart run vibeshield --json
```

### Sample Output:
```text
======================================================================
      🛡️   VIBESHIELD FLUTTER & DART STATIC SECURITY SCANNER  🛡️
======================================================================
Scanning directory: /project/lib

❌ [CONFIRMED LEAK] src/api_client.dart:18:24
   • Variable Name: stripeSecretKey
   • Vulnerability: CWE-798 (Stripe Live Secret Key)
   • Masked Value:  sk_live_****7890
   • Recommended:   Move to environment variables or SecureKey

----------------------------------------------------------------------
Summary:
  Files Scanned:       32
  Confirmed Leaks:     1
  Entropy Warnings:    0
----------------------------------------------------------------------

❌ VIBESHIELD SCAN FAILED: Hardcoded credentials must be resolved before deployment.
```
*Exits with code `1` if confirmed secrets are found, making it plug-and-play for GitHub Actions, Bitrise, or Codemagic.*

---

## Native Dart String Extensions

VibeShield extends `String` with zero-overhead masking helpers:

```dart
final token = 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'; // vibeshield-ignore

// Partial mask (sk_live_****7890)
print(token.halfMasked);

// Full shape-preserving mask (0% character overlap)
print(token.fullMasked);

// Redact all embedded secrets in a multi-line string or JSON blob
print(apiResponseBody.redacted);

// AI-safe full redaction
print(llmPrompt.aiSafe);
```

---

## Fluent Structured Logging

Log structured diagnostic events with automatic recursive sanitization:

```dart
VibeShield.log('Payment processed', LogLevel.info)
    .tag('CHECKOUT')
    .data({
      'userId': 94103,
      'amount': 89.00,
      'stripeKey': 'sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890', // Redacted! // vibeshield-ignore
      'jwt': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...', // Redacted!
      'randomHash': 'aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd', // Redacted by Entropy!
    })
    .send();
```

---

## Crashlytics & Sentry Telemetry Hook

Want to know when secrets are being leaked in debug environments without capturing the secret itself? Use the non-custodial telemetry hook:

```dart
VibeShield.onRedacted = (RedactionEvent event) {
  // Safe to pipe to Crashlytics or Sentry:
  // event.ruleName      -> "Stripe Live Secret Key"
  // event.category      -> "payment"
  // event.maskedPreview -> "sk_live_****7890" (ZERO raw secret data)
  // event.timestamp     -> DateTime
  print('[Security Audit] Intercepted leak of ${event.ruleName}');
};
```

---

## Supported Secret Rules

VibeShield includes a high-precision regex engine and Shannon entropy analyzer mapped to [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Hardcoded Credentials) and [CWE-532](https://cwe.mitre.org/data/definitions/532.html) (Information Exposure Through Log Files):

- **Stripe Keys:** Live secret keys (`sk_live_...`), restricted keys (`rk_live_...`).
- **AWS Credentials:** Access Key IDs (`AKIA...`), Secret Access Keys.
- **GitHub Tokens:** Personal Access Tokens (`ghp_...`), Fine-grained PATs (`github_pat_...`), OAuth tokens (`gho_...`).
- **Slack Tokens:** Bot (`xoxb-...`), User (`xoxp-...`), App (`xoxa-...`) tokens.
- **JSON Web Tokens (JWT):** Full 3-part Base64 URL encoded structures.
- **Private Keys:** RSA/EC/OpenSSH/PGP PEM blocks.
- **Database Connection URIs:** PostgreSQL, MySQL, MongoDB, Redis connection URLs with credentials.
- **Shannon Entropy Engine:** Unknown random tokens with entropy $\ge 4.5$ (Base64) or $\ge 3.0$ (Hex).

---

## Backward Compatibility

Existing code using `SecureLog` works with 100% compatibility:

```dart
SecureLog.print('User token: sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
