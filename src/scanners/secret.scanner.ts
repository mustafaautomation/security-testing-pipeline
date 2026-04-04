import fs from 'fs';
import path from 'path';
import { Finding, ScanResult, ScannerConfig } from '../core/types';
import { shouldFail } from '../core/pipeline';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Finding['severity'];
  cwe: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    cwe: 'CWE-798',
  },
  {
    name: 'AWS Secret Key',
    pattern:
      /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/g,
    severity: 'critical',
    cwe: 'CWE-798',
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: 'critical',
    cwe: 'CWE-798',
  },
  {
    name: 'Generic API Key',
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9]{20,}['"]?/gi,
    severity: 'high',
    cwe: 'CWE-798',
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    severity: 'critical',
    cwe: 'CWE-321',
  },
  {
    name: 'Password in Variable',
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
    severity: 'high',
    cwe: 'CWE-798',
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g,
    severity: 'medium',
    cwe: 'CWE-522',
  },
];

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', '__pycache__']);
const SKIP_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.gif',
  '.ico',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.lock',
]);

function walkFiles(dir: string): string[] {
  const files: string[] = [];

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...walkFiles(fullPath));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name);
      if (!SKIP_EXTENSIONS.has(ext)) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

export function runSecretScan(target: string, config: ScannerConfig): ScanResult {
  const start = Date.now();
  const findings: Finding[] = [];

  const files = walkFiles(target);

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');

    for (const pattern of SECRET_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        // Reset regex state
        pattern.pattern.lastIndex = 0;
        if (pattern.pattern.test(lines[i])) {
          findings.push({
            id: `secret-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
            title: `${pattern.name} detected`,
            severity: pattern.severity,
            scanType: 'secret',
            file: path.relative(target, file),
            line: i + 1,
            description: `Potential ${pattern.name} found in source code`,
            remediation:
              'Remove the secret and rotate the credential. Use environment variables or a secret manager.',
            cwe: pattern.cwe,
          });
        }
      }
    }
  }

  const result: ScanResult = {
    scanType: 'secret',
    scanner: 'Built-in Secret Scanner',
    timestamp: new Date().toISOString(),
    duration: Date.now() - start,
    findings,
    passed: true,
  };

  result.passed = !shouldFail(result, config.failOnSeverity);
  return result;
}
