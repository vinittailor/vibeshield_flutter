import 'dart:io';
import 'vibeshield.dart';
import 'secure_log.dart' as legacy;

/// An AI-proof wrapper for sensitive credentials.
///
/// Whenever this secret is printed, converted to string, serialized to JSON,
/// or inspected by an AI assistant in your editor, [toString] and [toJson]
/// ONLY return the masked representation (e.g. `sk_live_****7890`).
///
/// To pass the real credential to your HTTPS network client, explicitly call [exposeRaw].
///
/// Example:
/// ```dart
/// final stripeKey = SecureKey('sk_live_51Hc29KJ8f3ks9fQ2ABCDEF1234567890'); // vibeshield-ignore
///
/// print('Key: $stripeKey'); // Prints: Key: sk_live_****7890 (Safe from AI context!)
///
/// // Only exposed at the moment of HTTP network handshake:
/// final response = await dio.post(
///   '/charge',
///   options: Options(headers: {'Authorization': 'Bearer ${stripeKey.exposeRaw()}'}),
/// );
/// ```
class SecureKey {
  final String _raw;
  final legacy.MaskMode _maskMode;

  const SecureKey(this._raw, {legacy.MaskMode maskMode = legacy.MaskMode.partial})
      : _maskMode = maskMode;

  /// Safe masked representation (AI tools and loggers only see the mask!).
  @override
  String toString() => VibeShield.mask(_raw, overrideMode: _maskMode);

  /// Safe JSON serialization.
  dynamic toJson() => toString();

  /// Explicitly retrieves the raw credential for the final HTTPS network call.
  String exposeRaw() => _raw;

  int get length => _raw.length;
}

/// AI Shield file generator for Flutter & Dart projects.
/// Automatically creates and maintains `.cursorignore`, `.copilotignore`,
/// `.claudeignore`, and `.aiexclude` to prevent AI coding assistants from indexing
/// sensitive environment files, key stores, and configuration files.
class AiShield {
  static const List<String> managedAiIgnoreFiles = [
    '.cursorignore',
    '.copilotignore',
    '.claudeignore',
    '.aiexclude',
  ];

  static const List<String> defaultShieldRules = [
    '# --- VibeShield Managed AI-Ignore Rules ---',
    '# Protects sensitive Flutter & Dart files from AI indexing and prompt context',
    '.env',
    '.env.*',
    '*.env',
    '*.properties',
    'key.properties',
    'local.properties',
    'google-services.json',
    'GoogleService-Info.plist',
    '*.keystore',
    '*.jks',
    '*.p12',
    '*.pem',
    '*.key',
    '*secret*',
    '*credential*',
    '# --- End VibeShield Managed Rules ---',
  ];

  /// Generates or updates AI-ignore files in the given directory (defaults to current dir).
  static List<String> protectProject([String? rootPath]) {
    final root = Directory(rootPath ?? Directory.current.path);
    final updated = <String>[];

    for (final filename in managedAiIgnoreFiles) {
      final file = File('${root.path}/$filename');
      final content = defaultShieldRules.join('\n') + '\n';

      if (!file.existsSync()) {
        file.writeAsStringSync(content);
        updated.add(filename);
      } else {
        final existing = file.readAsStringSync();
        if (!existing.contains('# --- VibeShield Managed AI-Ignore Rules ---')) {
          file.writeAsStringSync('$existing\n\n$content');
          updated.add(filename);
        }
      }
    }

    return updated;
  }
}
