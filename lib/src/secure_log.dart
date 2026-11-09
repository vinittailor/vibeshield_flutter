/// Secure logging for Dart and Flutter with tree-shakable release build elimination.
library vibeshield.secure_log;

import 'masker.dart';
import 'rules.dart';
import 'entropy.dart';

/// Equivalent to Flutter's kDebugMode in pure Dart / Flutter environments.
/// In release mode (`dart.vm.product == true`), this evaluates to a compile-time false,
/// enabling Dart's AOT compiler to tree-shake out all code inside `if (kDebugMode)`.
const bool kDebugMode = !bool.fromEnvironment('dart.vm.product');

enum MaskMode { off, partial, full }

enum LogLevel { debug, info, warn, error }

/// Non-custodial redaction event (Never contains raw secret strings).
class RedactionEvent {
  final String ruleName;
  final String category;
  final String maskedPreview;
  final DateTime timestamp;
  final String source;

  const RedactionEvent({
    required this.ruleName,
    required this.category,
    required this.maskedPreview,
    required this.timestamp,
    required this.source,
  });

  @override
  String toString() =>
      'RedactionEvent($ruleName, category: $category, preview: $maskedPreview, time: $timestamp)';
}

class SecureLog {
  static MaskMode mode = MaskMode.partial;
  static final Set<String> _exactMatches = {};
  static final List<DartSecretRule> _customRules = [];
  static void Function(String message)? customPrinter;

  /// Optional event callback fired whenever a secret is redacted.
  /// Strictly non-custodial: only sends masked preview and metadata, never raw secrets.
  static void Function(RedactionEvent event)? onRedacted;

  /// Register exact match strings to redact (e.g. from local environment / .env).
  static void addExactMatches(List<String> secrets) {
    for (final s in secrets) {
      if (s.trim().length >= 4) {
        _exactMatches.add(s.trim());
      }
    }
  }

  /// Register custom secret rules specific to your application or domain.
  static void addRules(List<DartSecretRule> rules) {
    _customRules.addAll(rules);
  }

  /// Clears registered custom rules.
  static void clearRules() {
    _customRules.clear();
  }

  /// Convenience single-value masking helper.
  static String mask(String secret, {MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off || secret.isEmpty) return secret;
    if (activeMode == MaskMode.full) {
      return fullMask(secret);
    }
    return partialMask(secret);
  }

  /// Recursively sanitizes any dynamic object (Map, List, Set, or primitive).
  /// Every string inside metadata is redacted automatically.
  static dynamic sanitize(dynamic value, {MaskMode? overrideMode}) {
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
  /// Checks exact matches, canonical rules, custom rules, and Shannon entropy.
  static String redact(String message, {MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off || message.isEmpty) return message;

    var sanitized = message;

    // 1. Redact exact matches (e.g. loaded from .env)
    for (final exact in _exactMatches) {
      if (sanitized.contains(exact)) {
        final replacement = activeMode == MaskMode.full ? fullMask(exact) : partialMask(exact);
        sanitized = sanitized.replaceAll(exact, replacement);
        onRedacted?.call(RedactionEvent(
          ruleName: 'Exact Match',
          category: 'exact',
          maskedPreview: replacement,
          timestamp: DateTime.now(),
          source: 'flutter-sdk',
        ));
      }
    }

    // 2. Redact pattern rules (canonical + custom)
    final allRules = [...defaultDartRules, ..._customRules];
    for (final rule in allRules) {
      sanitized = sanitized.replaceAllMapped(rule.regex, (match) {
        final raw = match.group(1) ?? match.group(0)!;
        final replacement = activeMode == MaskMode.full
            ? fullMask(raw)
            : partialMask(raw, prefix: rule.prefix);
        onRedacted?.call(RedactionEvent(
          ruleName: rule.name,
          category: rule.category,
          maskedPreview: replacement,
          timestamp: DateTime.now(),
          source: 'flutter-sdk',
        ));
        return replacement;
      });
    }

    // 3. Fallback: Scan and redact high-entropy unknown tokens
    final entropyMatches = scanHighEntropyTokens(sanitized);
    if (entropyMatches.isNotEmpty) {
      // Replace from end to start to preserve string indices
      final sorted = List.of(entropyMatches)..sort((a, b) => b.start.compareTo(a.start));
      for (final em in sorted) {
        final replacement = activeMode == MaskMode.full ? fullMask(em.token) : partialMask(em.token);
        sanitized = sanitized.replaceRange(em.start, em.end, replacement);
        onRedacted?.call(RedactionEvent(
          ruleName: 'High-Entropy Token',
          category: 'entropy',
          maskedPreview: replacement,
          timestamp: DateTime.now(),
          source: 'flutter-sdk',
        ));
      }
    }

    return sanitized;
  }

  /// Logs a sanitized message with optional structured metadata.
  ///
  /// Zero production footprint: Gated by `kDebugMode` so calls in release builds
  /// are provably removed by Dart's AOT tree-shaking compiler optimization.
  static void print(
    Object? object, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
    LogLevel level = LogLevel.info,
  }) {
    if (kDebugMode) {
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
        corePrint(output);
      }
    }
  }

  /// Convenience method for Debug level logging.
  static void debug(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: LogLevel.debug);

  /// Convenience method for Info level logging.
  static void info(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: LogLevel.info);

  /// Convenience method for Warning level logging.
  static void warn(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: LogLevel.warn);

  /// Convenience method for Error level logging.
  static void error(
    Object? message, {
    Map<String, dynamic>? metadata,
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) =>
      print(message, metadata: metadata, error: error, stackTrace: stackTrace, tag: tag, level: LogLevel.error);
}

/// Indirection for testing print outputs
void Function(Object? object) corePrint = (obj) => dartPrint(obj);

void dartPrint(Object? obj) {
  // ignore: avoid_print
  print(obj);
}
