/// Masking algorithms for VibeShield: Partial preview and Full shape-preserving mask.
library vibeshield.masker;

final RegExp _alphaRegex = RegExp(r'[a-zA-Z]');
final RegExp _digitRegex = RegExp(r'[0-9]');
final RegExp _knownPrefixes = RegExp(
  r'^(sk_live_|rk_live_|pk_live_|ghp_|gho_|github_pat_|xoxb-|xoxp-|AKIA|ASIA)',
);

/// Partial mask: preserves key prefixes and last 4 characters for debugging disambiguation.
/// Example: `sk_live_51Hc29KJ8f3ks9fQ2` -> `sk_live_****9fQ2`
String partialMask(String secret, {String? prefix}) {
  if (secret.isEmpty) return '';
  if (secret.length <= 6) return '****';

  var p = prefix;
  if (p == null) {
    final match = _knownPrefixes.firstMatch(secret);
    if (match != null) {
      p = match.group(0);
    }
  }

  if (p != null && secret.startsWith(p)) {
    final remaining = secret.substring(p.length);
    if (remaining.length <= 6) {
      return '$p****';
    }
    final suffix = remaining.substring(remaining.length - 4);
    return '$p****$suffix';
  }

  if (secret.length <= 10) {
    return '${secret.substring(0, 2)}****${secret.substring(secret.length - 2)}';
  }

  return '${secret.substring(0, 4)}****${secret.substring(secret.length - 4)}';
}

/// Full shape-preserving mask:
/// Letters and digits are replaced with class placeholders ('a'/'0'), separators kept.
/// Guarantees zero character-level overlap for all alphanumeric characters.
/// Example: `sk_live_51Hc29KJ8f3ks9fQ2` -> `aa_aaaa_00aa00aa0a0aa0aa0`
String fullMask(String secret) {
  if (secret.isEmpty) return '';

  final buffer = StringBuffer();
  for (var i = 0; i < secret.length; i++) {
    final char = secret[i];
    if (_alphaRegex.hasMatch(char)) {
      // Map to 'a'. If original char was 'a' or 'A', map to 'b' for 0% overlap
      buffer.write((char == 'a' || char == 'A') ? 'b' : 'a');
    } else if (_digitRegex.hasMatch(char)) {
      // Map to '0'. If original char was '0', map to '1' for 0% overlap
      buffer.write((char == '0') ? '1' : '0');
    } else {
      // Retain structural delimiters: _, -, :, /, ., @, =, ', "
      buffer.write(char);
    }
  }

  return buffer.toString();
}

/// Verifies whether fullMask achieved zero character-level overlap for all alphanumeric characters.
bool verifyZeroCharacterOverlap(String raw, String masked) {
  if (raw.length != masked.length) return false;
  for (var i = 0; i < raw.length; i++) {
    final r = raw[i];
    final m = masked[i];
    if (_alphaRegex.hasMatch(r) || _digitRegex.hasMatch(r)) {
      if (r.toLowerCase() == m.toLowerCase()) {
        return false;
      }
    }
  }
  return true;
}

