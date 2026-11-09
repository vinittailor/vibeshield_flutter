# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

### Added
- **Global Zero-Friction Hook (`VibeShield.run`)**: Intercepts and masks credentials from all `print()` calls across app code and 3rd-party dependencies.
- **Provable Zero Release Footprint**: `enableInRelease: false` (default) bypasses Dart Zones in `--release` APK and AAB builds via compile-time AOT tree-shaking (`!kDebugMode`).
- **3 Masking Modes**:
  - `MaskMode.off`: Raw strings passed through unmasked for controlled debugging.
  - `MaskMode.partial`: Truncated preview (e.g. `sk_live_****7890`) preserving the provider prefix.
  - `MaskMode.full`: Shape-preserving token masking with 0% character overlap guarantee.
- **Dio Interceptor (`VibeShieldDioInterceptor`)**: Sanitizes HTTP headers, query parameters, and JSON payloads in console logs while preserving valid tokens over the network wire.
- **AI Leak Protection (`SecureKey`)**: AI-proof key wrapper whose `toString()` and `toJson()` return masked strings, preventing IDE AI agents (Cursor, Copilot, Claude) from scraping raw credentials.
- **AI Prompt Sanitization (`VibeShield.aiSafe` & `String.aiSafe`)**: Replaces credentials with shape-preserving masks before passing contexts or prompts to LLMs (OpenAI, Gemini, Claude).
- **AI Ignore Shield (`dart run vibeshield --shield-ai` & `VibeShield.protectFromAi()`)**: Auto-generates `.cursorignore`, `.copilotignore`, `.claudeignore`, and `.aiexclude` to shield `.env` and keystores.
- **Static Security CLI Scanner (`bin/vibeshield.dart`)**: Audits Flutter code for hardcoded secrets (CWE-798, CWE-532) and pinpoints file, line, column, and variable name. Supports `--json` and CI exit code enforcement.
- **Shannon Entropy Engine**: Detects unknown proprietary tokens and passwords via Base64/Hex classification without requiring known provider prefixes.
- **Fluent Structured Logger**: `VibeShield.log('...').tag('...').data({...}).send()` with recursive Map/List sanitization.
- **Native String Extensions**: `.masked`, `.halfMasked`, `.fullMasked`, `.redacted`, `.aiSafe`, and `.maskWith(mode)`.
- **Non-Custodial Audit Hook**: `VibeShield.onRedacted` callback for non-custodial telemetry forwarding (e.g. Sentry, Crashlytics).
- **Backward Compatibility**: Full backward compatibility with `SecureLog.print` and `SecureLog.mask`.

