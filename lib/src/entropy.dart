import 'dart:math' as math;

/// Shannon Entropy calculation and high-entropy secret detection for Dart/Flutter.
/// Grounded in information theory and Yelp detect-secrets heuristics.

/// Calculates Shannon entropy in bits per character.
double calculateShannonEntropy(String str) {
  if (str.isEmpty) return 0.0;

  final frequencies = <int, int>{};
  for (var i = 0; i < str.length; i++) {
    final code = str.codeUnitAt(i);
    frequencies[code] = (frequencies[code] ?? 0) + 1;
  }

  var entropy = 0.0;
  final len = str.length;
  for (final count in frequencies.values) {
    final p = count / len;
    entropy -= p * (math.log(p) / math.ln2);
  }

  return entropy;
}

bool isHexString(String str) => RegExp(r'^[0-9a-fA-F]+$').hasMatch(str);

bool isBase64String(String str) => RegExp(r'^[0-9a-zA-Z+/=_-]+$').hasMatch(str);

/// Determines whether a candidate token qualifies as a high-entropy secret.
bool isHighEntropyToken(
  String token, {
  double? threshold,
  int minLength = 20,
  String contextPrefix = '',
}) {
  if (token.length < minLength) return false;

  // Filter out purely numeric strings
  if (RegExp(r'^[0-9]+$').hasMatch(token)) return false;

  // Filter out simple lowercase single words
  if (RegExp(r'^[a-z]+$').hasMatch(token)) return false;

  // Filter out standard UUIDs
  if (RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', caseSensitive: false).hasMatch(token)) {
    return false;
  }

  // Reject exact-length hex digests in isolation (SHA-1, SHA-256, MD5) unless preceded by secret keywords
  if (isHexString(token) && (token.length == 32 || token.length == 40 || token.length == 64 || token.length == 128)) {
    final hasSecretKeyword = RegExp(
      r'(?:secret|api[_-]?key|token|auth|password|pwd|credential|private[_-]?key)\s*[:=]',
      caseSensitive: false,
    ).hasMatch(contextPrefix);
    if (!hasSecretKeyword) {
      return false;
    }
  }

  final entropy = calculateShannonEntropy(token);

  if (threshold != null) {
    return entropy >= threshold;
  }

  if (isHexString(token)) {
    return token.length >= 32 && entropy >= 3.5;
  }

  if (isBase64String(token)) {
    return token.length >= 20 && entropy >= 4.1;
  }

  return false;
}

class EntropyMatch {
  final int start;
  final int end;
  final String token;
  final double entropy;

  const EntropyMatch({
    required this.start,
    required this.end,
    required this.token,
    required this.entropy,
  });
}

/// Scans text for high-entropy tokens.
List<EntropyMatch> scanHighEntropyTokens(
  String text, {
  int minLength = 20,
  double? threshold,
}) {
  final matches = <EntropyMatch>[];
  final tokenRegex = RegExp(r'\b[A-Za-z0-9_=-]{16,}\b');

  for (final match in tokenRegex.allMatches(text)) {
    final rawMatch = match.group(0)!;
    final token = rawMatch.replaceAll(RegExp(r'^[_=-]+|[_=-]+$'), '');
    final startOffset = rawMatch.indexOf(token);
    final start = match.start + (startOffset >= 0 ? startOffset : 0);
    final end = start + token.length;

    final prefixStart = math.max(0, start - 35);
    final contextPrefix = text.substring(prefixStart, start);

    // Skip data:image/ or base64 data URLs
    if (RegExp(r'data:image\/[a-zA-Z+]+;base64,$', caseSensitive: false).hasMatch(contextPrefix)) {
      continue;
    }

    if (token.length >= minLength &&
        isHighEntropyToken(token, threshold: threshold, minLength: minLength, contextPrefix: contextPrefix)) {
      final entropy = calculateShannonEntropy(token);
      matches.pushOrAdd(
        EntropyMatch(
          start: start,
          end: end,
          token: token,
          entropy: entropy,
        ),
      );
    }
  }

  return matches;
}

extension _ListHelper on List<EntropyMatch> {
  void pushOrAdd(EntropyMatch item) => add(item);
}

