import 'dart:io';
import 'package:vibeshield_flutter/vibeshield_flutter.dart';

/// VibeShield CLI Scanner for Flutter & Dart projects.
///
/// Run from any Flutter or Dart project root:
/// ```bash
/// dart run vibeshield
/// ```
void main(List<String> args) {
  final targetPath = _parseArg(args, '--path') ?? '.';
  final jsonOutput = args.contains('--json');
  final failOnWarning = args.contains('--fail-on-warning');

  final scanDir = Directory(targetPath);
  if (!scanDir.existsSync()) {
    stderr.writeln('Error: Directory does not exist: $targetPath');
    exit(2);
  }

  // Check for --shield-ai flag to auto-generate AI protection ignore files
  if (args.contains('--shield-ai') || args.contains('--protect-ai')) {
    final updated = VibeShield.protectFromAi(scanDir.path);
    stdout.writeln('🛡️  VibeShield AI Shield activated!');
    stdout.writeln('Created/updated ${updated.length} AI-ignore file(s) to block AI tools:');
    for (final f in updated) {
      stdout.writeln('  • $f');
    }
    stdout.writeln('\nYour .env, key.properties, and secrets are now blocked from Cursor, Copilot, Claude, and JetBrains AI.');
    exit(0);
  }

  if (!jsonOutput) {
    stdout.writeln('======================================================================');
    stdout.writeln('      🛡️  VIBESHIELD FLUTTER & DART STATIC SECURITY SCANNER  🛡️');
    stdout.writeln('======================================================================');
    stdout.writeln('Scanning directory: ${scanDir.absolute.path}\n');
  }

  final files = _findFilesToScan(scanDir);
  final findings = <ScanFinding>[];

  for (final file in files) {
    try {
      final lines = file.readAsLinesSync();
      final relPath = _relativePath(scanDir.path, file.path);

      for (var lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        final line = lines[lineIdx];

        // Respect inline ignore comments: // vibeshield-ignore or # vibeshield-ignore
        if (line.toLowerCase().contains('vibeshield-ignore')) {
          continue;
        }

        // 1. Scan canonical rules
        for (final rule in defaultDartRules) {
          for (final match in rule.regex.allMatches(line)) {
            final raw = match.group(1) ?? match.group(0)!;
            findings.add(ScanFinding(
              filePath: relPath,
              line: lineIdx + 1,
              column: match.start + 1,
              ruleName: rule.name,
              category: rule.category,
              cwe: rule.cwe,
              confidence: 'confirmed',
              maskedPreview: VibeShield.mask(raw, overrideMode: MaskMode.partial),
              variableName: _extractVarName(line),
            ));
          }
        }

        // 2. Scan Shannon entropy tokens
        final entropyMatches = scanHighEntropyTokens(line);
        for (final em in entropyMatches) {
          // Check if not already covered by pattern
          final alreadyCovered = findings.any((f) =>
              f.filePath == relPath &&
              f.line == lineIdx + 1 &&
              (f.column - 1) <= em.start &&
              (f.column - 1 + em.token.length) >= em.end);

          if (!alreadyCovered) {
            findings.add(ScanFinding(
              filePath: relPath,
              line: lineIdx + 1,
              column: em.start + 1,
              ruleName: 'Potential High-Entropy Secret',
              category: 'entropy',
              cwe: 'CWE-798',
              confidence: 'entropy',
              maskedPreview: VibeShield.mask(em.token, overrideMode: MaskMode.partial),
              variableName: _extractVarName(line),
            ));
          }
        }
      }
    } catch (_) {
      // Skip unreadable / binary files
    }
  }

  final confirmed = findings.where((f) => f.confidence == 'confirmed').toList();
  final warnings = findings.where((f) => f.confidence == 'entropy').toList();

  if (jsonOutput) {
    stdout.writeln(_toJsonOutput(files.length, confirmed, warnings));
  } else {
    if (findings.isEmpty) {
      stdout.writeln('✅ ALL CLEAN: No leaked API keys or credentials detected across ${files.length} file(s).');
      stdout.writeln('======================================================================\n');
      exit(0);
    }

    // Print confirmed issues
    for (final f in confirmed) {
      stdout.writeln('❌ [LEAK DETECTED] ${f.filePath}:${f.line}:${f.column}');
      stdout.writeln('   • Variable Name: ${f.variableName}');
      stdout.writeln('   • Vulnerability: ${f.cwe} (${f.ruleName})');
      stdout.writeln('   • Masked Value:  ${f.maskedPreview}');
      stdout.writeln('   • Recommended:   Move to .env or flutter_dotenv\n');
    }

    // Print entropy warnings
    for (final w in warnings) {
      stdout.writeln('⚠️  [POTENTIAL ENTROPY] ${w.filePath}:${w.line}:${w.column}');
      stdout.writeln('   • Variable Name: ${w.variableName}');
      stdout.writeln('   • Vulnerability: ${w.cwe} (${w.ruleName})');
      stdout.writeln('   • Masked Value:  ${w.maskedPreview}\n');
    }

    stdout.writeln('----------------------------------------------------------------------');
    stdout.writeln('Summary:');
    stdout.writeln('  Files Scanned:       ${files.length}');
    stdout.writeln('  Confirmed Leaks:     ${confirmed.length}');
    stdout.writeln('  Entropy Warnings:    ${warnings.length}');
    stdout.writeln('----------------------------------------------------------------------');

    if (confirmed.isNotEmpty || (failOnWarning && warnings.isNotEmpty)) {
      stderr.writeln('\n❌ VIBESHIELD SCAN FAILED: Hardcoded credentials must be resolved before deployment.');
      exit(1);
    } else {
      stdout.writeln('\n✅ PASSED: No confirmed credentials found.');
      exit(0);
    }
  }
}

class ScanFinding {
  final String filePath;
  final int line;
  final int column;
  final String ruleName;
  final String category;
  final String cwe;
  final String confidence;
  final String maskedPreview;
  final String variableName;

  const ScanFinding({
    required this.filePath,
    required this.line,
    required this.column,
    required this.ruleName,
    required this.category,
    required this.cwe,
    required this.confidence,
    required this.maskedPreview,
    required this.variableName,
  });
}

List<File> _findFilesToScan(Directory root) {
  final result = <File>[];
  final ignoredDirs = {
    '.git',
    '.dart_tool',
    'build',
    '.gradle',
    '.idea',
    'node_modules',
    'Pods',
    '.symlinks',
  };

  try {
    for (final entity in root.listSync(recursive: true, followLinks: false)) {
      if (entity is File) {
        final path = entity.path.replaceAll('\\', '/');
        final isIgnored = ignoredDirs.any((d) => path.contains('/$d/') || path.startsWith('$d/'));
        if (isIgnored) continue;

        // Skip lock files and compiled assets
        if (path.endsWith('.lock') || path.endsWith('.lockb') || path.endsWith('.png') || path.endsWith('.jpg')) {
          continue;
        }

        // Target source code and configuration files
        if (path.endsWith('.dart') ||
            path.endsWith('.yaml') ||
            path.endsWith('.yml') ||
            path.endsWith('.json') ||
            path.endsWith('.properties') ||
            path.endsWith('.env') ||
            path.endsWith('.gradle') ||
            path.endsWith('.xml') ||
            path.endsWith('.plist')) {
          result.add(entity);
        }
      }
    }
  } catch (_) {}

  return result;
}

String _extractVarName(String line) {
  final match = RegExp(r'(?:const|let|var|final|String|val|def)\s+([A-Za-z0-9_$]+)\s*[:=]').firstMatch(line) ??
      RegExp(r'''["']?([A-Za-z0-9_$-]+)["']?\s*[:=]''').firstMatch(line);
  return match != null ? match.group(1)! : 'unnamed';
}

String _relativePath(String root, String file) {
  var normRoot = root.replaceAll('\\', '/');
  if (normRoot.endsWith('/')) normRoot = normRoot.substring(0, normRoot.length - 1);
  var normFile = file.replaceAll('\\', '/');
  if (normFile.startsWith('$normRoot/')) {
    return normFile.substring(normRoot.length + 1);
  }
  return normFile;
}

String? _parseArg(List<String> args, String prefix) {
  for (final a in args) {
    if (a.startsWith('$prefix=')) {
      return a.substring(prefix.length + 1);
    }
  }
  return null;
}

String _toJsonOutput(int fileCount, List<ScanFinding> confirmed, List<ScanFinding> warnings) {
  final buffer = StringBuffer();
  buffer.writeln('{');
  buffer.writeln('  "filesScanned": $fileCount,');
  buffer.writeln('  "confirmedLeaks": ${confirmed.length},');
  buffer.writeln('  "warnings": ${warnings.length},');
  buffer.writeln('  "passed": ${confirmed.isEmpty},');
  buffer.writeln('  "findings": [');
  final all = [...confirmed, ...warnings];
  for (var i = 0; i < all.length; i++) {
    final f = all[i];
    final comma = i == all.length - 1 ? '' : ',';
    buffer.writeln(
        '    {"file": "${f.filePath}", "line": ${f.line}, "column": ${f.column}, "rule": "${f.ruleName}", "cwe": "${f.cwe}", "variable": "${f.variableName}", "preview": "${f.maskedPreview}"}$comma');
  }
  buffer.writeln('  ]');
  buffer.writeln('}');
  return buffer.toString();
}

