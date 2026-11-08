/// Secure logging for Dart and Flutter with tree-shakable release build elimination.
library vibeshield.secure_log;

import 'masker.dart';
import 'rules.dart';

/// Equivalent to Flutter's kDebugMode in pure Dart / Flutter environments.
/// In release mode (`dart.vm.product == true`), this evaluates to a compile-time false,
/// enabling Dart's AOT compiler to tree-shake out all code inside `if (kDebugMode)`.
const bool kDebugMode = !bool.fromEnvironment('dart.vm.product');

enum MaskMode { off, partial, full }

class SecureLog {
  static MaskMode mode = MaskMode.partial;
  static final Set<String> _exactMatches = {};
  static void Function(String message)? customPrinter;

  /// Register exact match strings to redact (e.g. from local environment).
  static void addExactMatches(List<String> secrets) {
    for (final s in secrets) {
      if (s.trim().length >= 4) {
        _exactMatches.add(s.trim());
      }
    }
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

  /// Redacts sensitive credentials across any string message.
  static String redact(String message, {MaskMode? overrideMode}) {
    final activeMode = overrideMode ?? mode;
    if (activeMode == MaskMode.off || message.isEmpty) return message;

    var sanitized = message;

    // 1. Redact exact matches
    for (final exact in _exactMatches) {
      if (sanitized.contains(exact)) {
        final replacement = activeMode == MaskMode.full ? fullMask(exact) : partialMask(exact);
        sanitized = sanitized.replaceAll(exact, replacement);
      }
    }

    // 2. Redact pattern rules
    for (final rule in defaultDartRules) {
      sanitized = sanitized.replaceAllMapped(rule.regex, (match) {
        final raw = match.group(1) ?? match.group(0)!;
        final replacement = activeMode == MaskMode.full
            ? fullMask(raw)
            : partialMask(raw, prefix: rule.prefix);
        return replacement;
      });
    }

    return sanitized;
  }

  /// Logs a sanitized message.
  /// Zero production footprint: Gated by `kDebugMode` so that calls in release builds
  /// are provably removed by Dart's AOT tree-shaking compiler optimization.
  static void print(Object? object) {
    if (kDebugMode) {
      final text = object?.toString() ?? 'null';
      final output = redact(text);

      if (customPrinter != null) {
        customPrinter!(output);
      } else {
        // Standard Dart print
        // ignore: avoid_print
        corePrint(output);
      }
    }
  }
}

/// Indirection for testing print outputs
void Function(Object? object) corePrint = (obj) => dartPrint(obj);

void dartPrint(Object? obj) {
  // ignore: avoid_print
  print(obj);
}

