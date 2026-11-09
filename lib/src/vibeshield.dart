/// Unified VibeShield Flutter/Dart SDK combining:
/// 1. Zero-code global zone & print interception (`VibeShield.install()`, `VibeShield.run()`)
/// 2. Native Dart extension methods (`secret.masked`, `text.redacted`, `secret.fullMasked`)
/// 3. Structured fluent logging with auto-sanitized metadata (`VibeShield.info(...).data(...).send()`)
/// 4. Network header scrubbing (`VibeShield.sanitizeHeaders(...)`)
/// 5. Non-custodial audit callbacks (`VibeShield.onRedacted`)
/// 6. Provable zero release footprint (`kDebugMode` compiler tree-shaking)
library vibeshield.main;

import 'dart:async';
import 'masker.dart';
import 'rules.dart';
import 'entropy.dart';
import 'secure_log.dart' as legacy;

export 'masker.dart';
export 'rules.dart';
export 'entropy.dart';
export 'secure_log.dart' show MaskMode, LogLevel, RedactionEvent, kDebugMode;
export 'dio_interceptor.dart';

import 'dio_interceptor.dart';

/// Backward-compatibility alias
typedef SecureLog = VibeShield;

class VibeShield {
  static legacy.MaskMode mode = legacy.MaskMode.partial;
  static final Set<String> _exactMatches = {};
  static final List<DartSecretRule> _customRules = [];
  static void Function(String message)? customPrinter;
  static bool _installed = false;

  /// Mode inspection getters
  static bool get isOff => mode == legacy.MaskMode.off;
  static bool get isPartial => mode == legacy.MaskMode.partial;
  static bool get isFull => mode == legacy.MaskMode.full;

  /// Sets the active masking mode:
  /// - `MaskMode.off`: No redaction (raw secret).
  /// - `MaskMode.partial`: Half mask / preview (`sk_live_****9fQ2`).
  /// - `MaskMode.full`: Shape-preserving full mask (`aa_aaaa_00aa...`, 0% character overlap).
  static void setMode(legacy.MaskMode newMode) {
    mode = newMode;
  }

  /// Cycles through masking modes: off -> partial -> full -> off.
  static legacy.MaskMode cycleMode() {
    switch (mode) {
      case legacy.MaskMode.off:
        mode = legacy.MaskMode.partial;
        break;
      case legacy.MaskMode.partial:
        mode = legacy.MaskMode.full;
        break;
      case legacy.MaskMode.full:
        mode = legacy.MaskMode.off;
        break;
    }
    return mode;
  }

  /// Direct plug-and-play Dio Interceptor instance.
  /// Usage: `dio.interceptors.add(VibeShield.dioInterceptor());`
  /// Optionally override the masking mode specifically for Dio:
  /// `dio.interceptors.add(VibeShield.dioInterceptor(mode: MaskMode.full));`
  static VibeShieldDioInterceptor dioInterceptor({
    legacy.MaskMode? mode,
    bool enableInRelease = false,
    bool logRequests = true,
    bool logResponses = true,
    bool logErrors = true,
  }) =>
      VibeShieldDioInterceptor(
        overrideMode: mode,
        enableInRelease: enableInRelease,
        logRequests: logRequests,
        logResponses: logResponses,
        logErrors: logErrors,
      );

  /// Non-custodial audit callback hook (Safe for Sentry, Crashlytics, Telemetry).
  static void Function(legacy.RedactionEvent event)? onRedacted;

  // --------------------------------------------------------------------------
  // 1. GLOBAL ZERO-CODE INTERCEPTION (Better Way #1)
  // --------------------------------------------------------------------------

  /// Globally installs VibeShield into the active Dart/Flutter environment.
  /// Once installed, every standard `print(...)` in your app, third-party libraries,
  /// and the framework is automatically intercepted and redacted before display.
  ///
  /// In release builds (APK/AAB), if [enableInRelease] is false (default),
  /// installation is completely bypassed with zero overhead.
  static void install({
    legacy.MaskMode? initialMode,
    bool enableInRelease = false,
    List<String>? exactSecrets,
    void Function(legacy.RedactionEvent event)? onRedactionEvent,
  }) {
    if (!legacy.kDebugMode && !enableInRelease) {
      return;
    }

    if (initialMode != null) mode = initialMode;
    if (exactSecrets != null) addExactMatches(exactSecrets);
    if (onRedactionEvent != null) onRedacted = onRedactionEvent;

    if (!_installed) {
      _installed = true;
      // Redirect core print indirection to run redaction automatically
      legacy.corePrint = (obj) {
        final text = obj?.toString() ?? 'null';
        final sanitized = redact(text);
        if (customPrinter != null) {
          customPrinter!(sanitized);
        } else {
          legacy.dartPrint(sanitized);
        }
      };
    }
  }

  /// Runs an entire Flutter app or code block inside an isolated auto-redacting Dart Zone.
  ///
  /// In production release builds (e.g. building APK or AAB files), if [enableInRelease]
  /// is false (the default), VibeShield directly invokes [body] with ZERO Zone interception,
  /// ZERO overhead, and zero interference with production performance.
  ///
  /// Recommended pattern for Flutter `main()`:
  /// ```dart
  /// void main() => VibeShield.run(
  ///   () => runApp(const MyApp()),
  ///   mode: MaskMode.partial,
  ///   enableInRelease: false, // Provably calls runApp directly in release APK/AAB!
  /// );
  /// ```
  static R run<R>(
    R Function() body, {
    legacy.MaskMode? mode,
    bool enableInRelease = false,
    List<String>? exactSecrets,
    void Function(legacy.RedactionEvent event)? onRedactionEvent,
  }) {
    // In production release builds (APK/AAB), completely bypass VibeShield by default!
    if (!legacy.kDebugMode && !enableInRelease) {
      return body();
    }

    if (mode != null) VibeShield.mode = mode;
    if (exactSecrets != null) addExactMatches(exactSecrets);
    if (onRedactionEvent != null) onRedacted = onRedactionEvent;

    return runZoned(
      body,
      zoneSpecification: ZoneSpecification(
        print: (self, parent, zone, line) {
          final sanitized = redact(line);
          if (customPrinter != null) {
            customPrinter!(sanitized);
          } else {
            parent.print(zone, sanitized);
          }
        },
      ),
    );
  }

  // --------------------------------------------------------------------------
  // 2. SECRET REDACTION & MASKING CORE
  // --------------------------------------------------------------------------

  /// Register exact match strings to redact (e.g. from local environment / .env).
  static void addExactMatches(List<String> secrets) {
    for (final s in secrets) {
      if (s.trim().length >= 4) {
        _exactMatches.add(s.trim());
      }
    }
  }

  /// Register custom secret rules.
  static void addRules(List<DartSecretRule> rules) {
    _customRules.addAll(rules);
  }

  /// Clears registered custom rules.
  static void clearRules() {
    _customRules.clear();
  }

  /// Convenience single-value masking helper.
  static String mask(String secret, {legacy.MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == legacy.MaskMode.off || secret.isEmpty) return secret;
    if (activeMode == legacy.MaskMode.full) {
      return fullMask(secret);
    }
    return partialMask(secret);
  }

  /// Recursively sanitizes any dynamic object (Map, List, or primitive).
  static dynamic sanitize(dynamic value, {legacy.MaskMode? overrideMode}) {
    if (value == null) return null;
    if (value is String) {
      return redact(value, overrideMode: overrideMode);
    }
    if (value is Map) {
      final sanitizedMap = <dynamic, dynamic>{};
      for (final entry in value.entries) {
        final sanitizedKey = entry.key is String
            ? redact(entry.key as String, overrideMode: overrideMode)
            : entry.key;
        sanitizedMap[sanitizedKey] = sanitize(entry.value, overrideMode: overrideMode);
      }
      return sanitizedMap;
    }
    if (value is Iterable) {
      return value.map((item) => sanitize(item, overrideMode: overrideMode)).toList();
    }
    return value;
  }

  /// Redacts sensitive credentials across any string message.
  static String redact(String message, {legacy.MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == legacy.MaskMode.off || message.isEmpty) return message;

    var sanitized = message;

    // 1. Redact exact matches (.env, vault)
    for (final exact in _exactMatches) {
      if (sanitized.contains(exact)) {
        final replacement = activeMode == legacy.MaskMode.full ? fullMask(exact) : partialMask(exact);
        sanitized = sanitized.replaceAll(exact, replacement);
        _fireRedactedEvent('Exact Match', 'exact', replacement);
      }
    }

    // 2. Redact pattern rules (canonical + custom)
    final allRules = [...defaultDartRules, ..._customRules];
    for (final rule in allRules) {
      sanitized = sanitized.replaceAllMapped(rule.regex, (match) {
        final raw = match.group(1) ?? match.group(0)!;
        final replacement = activeMode == legacy.MaskMode.full
            ? fullMask(raw)
            : partialMask(raw, prefix: rule.prefix);
        _fireRedactedEvent(rule.name, rule.category, replacement);
        return replacement;
      });
    }

    // 3. Fallback: Shannon entropy detection for unknown tokens
    final entropyMatches = scanHighEntropyTokens(sanitized);
    if (entropyMatches.isNotEmpty) {
      final sorted = List.of(entropyMatches)..sort((a, b) => b.start.compareTo(a.start));
      for (final em in sorted) {
        final replacement = activeMode == legacy.MaskMode.full ? fullMask(em.token) : partialMask(em.token);
        sanitized = sanitized.replaceRange(em.start, em.end, replacement);
        _fireRedactedEvent('High-Entropy Token', 'entropy', replacement);
      }
    }

    return sanitized;
  }

  static void _fireRedactedEvent(String ruleName, String category, String maskedPreview) {
    onRedacted?.call(legacy.RedactionEvent(
      ruleName: ruleName,
      category: category,
      maskedPreview: maskedPreview,
      timestamp: DateTime.now(),
      source: 'flutter-sdk',
    ));
  }

  // --------------------------------------------------------------------------
  // 3. NETWORK & HTTP SCRUBBING (Better Way #3)
  // --------------------------------------------------------------------------

  /// Sanitizes HTTP headers map (e.g. Authorization, X-Api-Key, Cookie, Bearer tokens).
  static Map<String, dynamic> sanitizeHeaders(
    Map<String, dynamic> headers, {
    legacy.MaskMode? overrideMode,
  }) {
    final result = <String, dynamic>{};
    for (final entry in headers.entries) {
      final keyLower = entry.key.toLowerCase();
      if (keyLower.contains('auth') ||
          keyLower.contains('token') ||
          keyLower.contains('key') ||
          keyLower.contains('secret') ||
          keyLower.contains('cookie')) {
        result[entry.key] = redact(entry.value.toString(), overrideMode: overrideMode);
      } else {
        result[entry.key] = sanitize(entry.value, overrideMode: overrideMode);
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // 4. FLUENT STRUCTURED LOGGING (Better Way #4)
  // --------------------------------------------------------------------------

  /// Fluent log builder: `VibeShield.log('Checkout').tag('BILLING').data({...}).send()`
  static VibeShieldLogBuilder log(String message, [legacy.LogLevel level = legacy.LogLevel.info]) =>
      VibeShieldLogBuilder(message, level);

  /// Direct structured methods for each log level
  static void debug(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: legacy.LogLevel.debug);

  static void info(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: legacy.LogLevel.info);

  static void warn(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: legacy.LogLevel.warn);

  static void error(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: legacy.LogLevel.error);

  /// Direct structured print method.
  static void print(
    Object? object, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
    legacy.LogLevel level = legacy.LogLevel.info,
  }) {
    if (legacy.kDebugMode) {
      final text = object?.toString() ?? 'null';
      final sanitizedText = redact(text);
      final sanitizedMetadata = metadata != null ? sanitize(metadata) as Map : null;

      final buffer = StringBuffer();
      if (tag != null) {
        buffer.write('[$tag] ');
      }
      buffer.write(sanitizedText);

      if (sanitizedMetadata != null && sanitizedMetadata.isNotEmpty) {
        buffer.write(' | metadata: $sanitizedMetadata');
      }

      if (error != null) {
        final sanitizedError = sanitize(error.toString());
        buffer.write(' | error: $sanitizedError');
      }

      if (stackTrace != null) {
        buffer.write('\n$stackTrace');
      }

      final output = buffer.toString();

      if (customPrinter != null) {
        customPrinter!(output);
      } else {
        legacy.dartPrint(output);
      }
    }
  }
}

/// Fluent builder for structured logs with metadata, error, and tags.
class VibeShieldLogBuilder {
  final String _message;
  final legacy.LogLevel _level;
  String? _tag;
  Map<String, dynamic>? _metadata;
  Object? _error;
  StackTrace? _stackTrace;

  VibeShieldLogBuilder(this._message, [this._level = legacy.LogLevel.info]);

  VibeShieldLogBuilder tag(String tag) {
    _tag = tag;
    return this;
  }

  VibeShieldLogBuilder data(Map<String, dynamic> metadata) {
    _metadata = metadata;
    return this;
  }

  VibeShieldLogBuilder error(Object error, [StackTrace? stackTrace]) {
    _error = error;
    _stackTrace = stackTrace;
    return this;
  }

  void send() {
    VibeShield.print(
      _message,
      metadata: _metadata,
      error: _error,
      stackTrace: _stackTrace,
      tag: _tag,
      level: _level,
    );
  }
}

// --------------------------------------------------------------------------
// 5. NATIVE DART STRING EXTENSIONS (Better Way #2)
// --------------------------------------------------------------------------

/// Idiomatic Dart string extension for effortless secret masking.
extension VibeShieldStringExtension on String {
  /// Redacts all sensitive credentials contained in this string.
  String get redacted => VibeShield.redact(this);

  /// Masks this string as a single secret in partial (half) mode (e.g. `sk_live_****9fQ2`).
  String get masked => VibeShield.mask(this, overrideMode: legacy.MaskMode.partial);

  /// Half mask alias for partial mode.
  String get halfMasked => VibeShield.mask(this, overrideMode: legacy.MaskMode.partial);

  /// Masks this string in full shape-preserving mode (guaranteeing 0% character overlap).
  String get fullMasked => VibeShield.mask(this, overrideMode: legacy.MaskMode.full);

  /// Masks this string using an explicit mode.
  String maskWith(legacy.MaskMode mode) => VibeShield.mask(this, overrideMode: mode);
}
