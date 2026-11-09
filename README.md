# vibeshield_flutter

[![Pub Version](https://img.shields.io/pub/v/vibeshield_flutter.svg)](https://pub.dev/packages/vibeshield_flutter)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Dart SDK](https://img.shields.io/badge/Dart-3.0+-blue.svg)](https://dart.dev)
[![Platforms](https://img.shields.io/badge/Platforms-Android%20%7C%20iOS%20%7C%20Web%20%7C%20macOS%20%7C%20Windows%20%7C%20Linux-green.svg)](https://pub.dev/packages/vibeshield_flutter)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/vinittailor/vibeshield_flutter)

> **The Ultimate Flutter & Dart Secret Redaction SDK — 100% Pure Dart, zero custody, zero production footprint, and airtight protection against credential leaks in logs, AI coding assistants, and network traces.**

---

## Why VibeShield Flutter?

Every Flutter developer accidentally prints credentials during debugging: Stripe secret keys, Firebase tokens, JWTs, AWS credentials, or database URLs. These strings immediately leak into:

1. **Terminal & IDE Logs:** Visible to anyone watching your screen or recorded in CI logs ([CWE-532](https://cwe.mitre.org/data/definitions/532.html)).
2. **AI Coding Assistants:** Tools like Cursor, GitHub Copilot, and Claude Code continuously read your active editor context and terminal outputs, uploading raw keys to LLM servers.
3. **Crash & Telemetry Services:** Sentry or Firebase Crashlytics capture breadcrumbs with unredacted API tokens.
4. **Network Interceptors:** Dio logger interceptors print `Authorization: Bearer <secret>` and response payloads in plain text.

`vibeshield_flutter` solves all of this with **zero code friction**, **provable zero release overhead**, and **zero custody**.

---

## Package Specifications & Performance

| Metric | Specification | Details |
| :--- | :--- | :--- |
| **Language** | 100% Pure Dart | Zero native Android (Java/Kotlin) or iOS (Swift/Obj-C) dependencies. |
| **Download Size** | **~23 KB** | Ultra-lightweight archive; adds no bloat to your dependencies. |
| **Release Footprint** | **0 KB / 0% CPU** | Dart AOT compiler tree-shakes all Zone logging logic in release mode (`enableInRelease: false`). |
| **Platform Support** | Multiplatform | Android, iOS, Flutter Web, macOS, Windows, Linux, and standalone Dart CLI. |
| **Security Standards** | CWE-798 & CWE-532 | Mapped to MITRE standards for Hardcoded Credentials and Log File Exposure. |

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
- [Real-World Scenarios](#real-world-scenarios)
  - [Scenario 1: Authentication & JWT Login Response](#scenario-1-authentication--jwt-login-response)
  - [Scenario 2: Stripe SDK & Payment Gateway](#scenario-2-stripe-sdk--payment-gateway)
  - [Scenario 3: Non-Custodial Crashlytics & Sentry](#scenario-3-non-custodial-crashlytics--sentry)
  - [Scenario 4: CI/CD Pipeline Enforcement](#scenario-4-cicd-pipeline-enforcement)
- [Complete API Reference & Parameters](#complete-api-reference--parameters)
- [Supported Secret Rules](#supported-secret-rules)
- [Backward Compatibility](#backward-compatibility)
- [License](#license)

---

## Quick Start

### 1. Add Dependency

Add to your `pubspec.yaml`:

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
| `MaskMode.partial` (Default) | `sk_live_****7890` | Identifies provider prefix while concealing secret payload. Ideal for daily debugging. |
| `MaskMode.full` | `aa_aaaa_00aa00AA...` | Shape-preserving full mask with **0% character overlap guarantee**. Perfect for live streaming, recorded demos, and AI prompt context. |
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
- In **Release Mode** (`kDebugMode == false`), Dart's AOT compiler evaluates `!kDebugMode && !enableInRelease` to compile-time `true` and immediately executes `body()` directly. **Zero Dart Zones are spawned and zero logging logic is executed.**

---

## Dio Network Interceptor

When using [Dio](https://pub.dev/packages/dio), logging interceptors often expose raw `Authorization` headers, sensitive query params, and JSON request/response bodies in your terminal.

`VibeShieldDioInterceptor` sanitizes the logged output while **keeping the actual HTTP request untouched over the network wire**:

```dart
import 'package:dio/dio.dart';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

final dio = Dio();

// Add VibeShield interceptor in ONE line
dio.interceptors.add(VibeShield.dioInterceptor());

// Or configure with custom options
dio.interceptors.add(VibeShieldDioInterceptor(
  overrideMode: MaskMode.partial,
  enableInRelease: false, // Default: zero overhead in production
  logRequests: true,      // Log outgoing HTTP requests
  logResponses: true,     // Log incoming HTTP responses
  logErrors: true,        // Log Dio network exceptions
));
```

### What happens:
```text
--> POST https://api.stripe.com/v1/charges
Headers: {Authorization: Bearer sk_live_****7890}
Body: {"clientSecret": "sk_live_****7890", "amount": 2000}
```
*Live backend servers still receive the genuine `Authorization: Bearer sk_live_51Hc29...` token, so payments and authentication never fail!*

---

## AI Leak Protection

Modern AI developer tools (Cursor, Copilot, Claude Code) read code files, variables, and terminal outputs, unintentionally sending sensitive credentials to LLM cloud providers. VibeShield gives you 3 layers of defense:

### 1. `SecureKey` AI-Proof Wrapper

Wrap your keys in Dart code:

```dart
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

// Wrap your sensitive key once
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

## Real-World Scenarios

### Scenario 1: Authentication & JWT Login Response

When a user logs in, your server returns authentication tokens. Printing or logging the response often exposes tokens in the terminal:

```dart
final response = await dio.post('/api/auth/login', data: credentials);

// Even if you or a 3rd-party logger prints this:
print('User logged in successfully: ${response.data}');

// Raw response payload:
// {"userId": 1024, "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "refreshToken": "aB39xK7mQ2vL5pT8wR1yU4zE6nJ0sAbCd"}

// Terminal displays safely:
// User logged in successfully: {"userId": 1024, "token": "eyJh****...", "refreshToken": "aB39****AbCd"}

// Dart runtime code still accesses the genuine tokens:
final userToken = response.data['token']; // Valid unmasked string!
await flutterSecureStorage.write(key: 'jwt', value: userToken);
```

### Scenario 2: Stripe SDK & Payment Gateway

Client-side payments require initializing Stripe or gateway tokens:

```dart
final secretKey = SecureKey('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore

// Safe in logging:
VibeShield.log('Initializing payment intent', LogLevel.info)
    .data({'customer': 'cus_123', 'key': secretKey})
    .send();

// Expose only for the actual HTTPS request:
final paymentIntent = await stripeApi.createIntent(
  secret: secretKey.exposeRaw(),
  amount: 4900,
);
```

### Scenario 3: Non-Custodial Crashlytics & Sentry

Forward leak alerts to your telemetry pipeline without capturing the real secret:

```dart
VibeShield.onRedacted = (RedactionEvent event) {
  // Safe to send to Sentry or Firebase Crashlytics:
  FirebaseCrashlytics.instance.log(
    'Secret Redacted: ${event.ruleName} in category ${event.category}',
  );
  FirebaseCrashlytics.instance.setCustomKey('lastMaskedPreview', event.maskedPreview);
  // event.maskedPreview is sk_live_****7890 (ZERO raw secret data)
};
```

### Scenario 4: CI/CD Pipeline Enforcement

Add VibeShield to your GitHub Actions (`.github/workflows/security.yml`):

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
        with:
          channel: 'stable'
      - name: Install dependencies
        run: flutter pub get
      - name: Run VibeShield Static Audit
        run: dart run vibeshield --path=lib
```

---

## Complete API Reference & Parameters

### `VibeShield.run<R>(body, {...})`
Runs your app or code block inside an auto-redacting Dart Zone.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `body` | `R Function()` | **Required** | The closure to execute (e.g. `() => runApp(const MyApp())`). |
| `mode` | `MaskMode?` | `MaskMode.partial` | Initial masking mode ([MaskMode.partial], [MaskMode.full], or [MaskMode.off]). |
| `enableInRelease` | `bool` | `false` | When `false`, immediately executes `body()` with **zero Dart Zones and zero overhead** in release mode. |
| `exactSecrets` | `List<String>?` | `null` | Optional list of specific raw secret strings to always mask. |
| `onRedactionEvent`| `Function(RedactionEvent)?`| `null` | Non-custodial callback triggered whenever a secret is redacted. |

---

### `VibeShieldDioInterceptor({...})`
Dio interceptor that scrubs HTTP request/response logs.

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `overrideMode` | `MaskMode?` | `null` | Explicit mode override for Dio logs. Defaults to global `VibeShield.maskMode`. |
| `enableInRelease` | `bool` | `false` | When `false`, calls `handler.next()` directly in release builds with zero overhead. |
| `logRequests` | `bool` | `true` | Log outgoing HTTP requests (method, URI, sanitized headers, query params, and body). |
| `logResponses` | `bool` | `true` | Log incoming HTTP responses (status code, URI, and sanitized body). |
| `logErrors` | `bool` | `true` | Log Dio exceptions with sanitized error messages. |

---

### `SecureKey(raw, {maskMode})`
AI-proof key wrapper that hides credentials from string interpolation, `print()`, and JSON serialization.

| Parameter / Method | Type | Description |
| :--- | :--- | :--- |
| `raw` | `String` | The raw secret string. |
| `maskMode` | `MaskMode` | Masking mode to use in `toString()` (default: `MaskMode.partial`). |
| `toString()` | `String` | Returns masked string (e.g. `sk_live_****7890`). Prevents AI scraping. |
| `toJson()` | `dynamic` | Returns masked string for safe JSON serialization. |
| `exposeRaw()` | `String` | Explicitly returns the raw secret for HTTPS network calls. |

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
