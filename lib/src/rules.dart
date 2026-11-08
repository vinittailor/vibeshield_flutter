/// Canonical secret pattern rules for Dart/Flutter SDK, mirrored from /rules/.
library vibeshield.rules;

class DartSecretRule {
  final String id;
  final String name;
  final String category;
  final String cwe;
  final RegExp regex;
  final String? prefix;

  const DartSecretRule({
    required this.id,
    required this.name,
    required this.category,
    required this.cwe,
    required this.regex,
    this.prefix,
  });
}

final List<DartSecretRule> defaultDartRules = [
  DartSecretRule(
    id: 'stripe-secret-key',
    name: 'Stripe Live Secret Key',
    category: 'payment',
    cwe: 'CWE-798',
    regex: RegExp(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'),
    prefix: 'sk_live_',
  ),
  DartSecretRule(
    id: 'stripe-restricted-key',
    name: 'Stripe Live Restricted Key',
    category: 'payment',
    cwe: 'CWE-798',
    regex: RegExp(r'\b(rk_live_[0-9a-zA-Z]{24,})\b'),
    prefix: 'rk_live_',
  ),
  DartSecretRule(
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    category: 'cloud',
    cwe: 'CWE-798',
    regex: RegExp(r'\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b'),
  ),
  DartSecretRule(
    id: 'github-pat',
    name: 'GitHub Personal Access Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp(r'\b(ghp_[0-9a-zA-Z]{36})\b'),
    prefix: 'ghp_',
  ),
  DartSecretRule(
    id: 'slack-bot-token',
    name: 'Slack Bot Token',
    category: 'auth',
    cwe: 'CWE-798',
    regex: RegExp(r'\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b'),
    prefix: 'xoxb-',
  ),
  DartSecretRule(
    id: 'jwt-token',
    name: 'JSON Web Token (JWT)',
    category: 'auth',
    cwe: 'CWE-532',
    regex: RegExp(r'\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'),
    prefix: 'eyJ',
  ),
  DartSecretRule(
    id: 'database-connection-url',
    name: 'Database Connection URL',
    category: 'database',
    cwe: 'CWE-798',
    regex: RegExp(r'''\b((?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps):\/\/[^:\s"']+:[^@\s"']+@[^/\s"']+(?:\/[^\s"']*)?)\b'''),
  ),
];
