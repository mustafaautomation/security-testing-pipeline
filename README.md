# Security Testing Pipeline

[![CI](https://github.com/mustafaautomation/security-testing-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/mustafaautomation/security-testing-pipeline/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org)

Automated security scanning pipeline that orchestrates SAST (Semgrep), dependency auditing (npm audit), and secret detection. Normalizes findings into a unified format with severity-based fail gates for CI/CD integration.

---

## Scan Types

| Scanner | Type | Tool | What It Finds |
|---------|------|------|--------------|
| SAST | Static analysis | Semgrep | SQL injection, XSS, insecure patterns |
| Dependency | Supply chain | npm audit | Known CVEs in dependencies |
| Secret | Credential leak | Built-in | AWS keys, GitHub tokens, private keys, passwords |

---

## Quick Start

```bash
npm install security-testing-pipeline

# Run all scans on current directory
npx sec-scan scan .

# Secret detection only
npx sec-scan scan . --secrets

# Dependency audit only
npx sec-scan scan . --deps

# SAST only (requires Semgrep installed)
npx sec-scan scan . --sast

# Fail only on critical (default: high)
npx sec-scan scan . --fail-on critical

# JSON output
npx sec-scan scan . --json report.json
```

The CLI exits with code 1 if any findings meet or exceed the `--fail-on` severity.

---

## Library API

```typescript
import {
  runSecretScan,
  runDependencyScan,
  runSastScan,
  buildReport,
} from 'security-testing-pipeline';

const results = [
  runSecretScan('.', { enabled: true, failOnSeverity: 'high' }),
  runDependencyScan('.', { enabled: true, failOnSeverity: 'critical' }),
];

const report = buildReport('.', results);
// report.overallPassed, report.summary.critical, etc.
```

---

## Secret Detection Patterns

| Pattern | Severity | CWE |
|---------|----------|-----|
| AWS Access Key (`AKIA...`) | Critical | CWE-798 |
| AWS Secret Key | Critical | CWE-798 |
| GitHub Token (`ghp_...`) | Critical | CWE-798 |
| Private Key (`-----BEGIN...`) | Critical | CWE-321 |
| Generic API Key | High | CWE-798 |
| Password in variable | High | CWE-798 |
| JWT Token | Medium | CWE-522 |

Skips `node_modules/`, `.git/`, binary files, and lock files.

---

## Finding Format

All scanners normalize output to a unified `Finding` type:

```typescript
interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  scanType: 'sast' | 'dependency' | 'secret' | 'dast';
  file?: string;
  line?: number;
  description: string;
  remediation: string;
  cwe?: string;
  reference?: string;
}
```

---

## Project Structure

```
security-testing-pipeline/
├── src/
│   ├── core/
│   │   ├── types.ts             # Finding, ScanResult, PipelineReport types
│   │   └── pipeline.ts          # Report builder, severity logic
│   ├── scanners/
│   │   ├── sast.scanner.ts      # Semgrep integration
│   │   ├── dependency.scanner.ts # npm audit parser
│   │   └── secret.scanner.ts    # Pattern-based secret detection
│   ├── reporters/
│   │   ├── console.reporter.ts  # Colored terminal output
│   │   └── json.reporter.ts     # JSON file output
│   ├── cli.ts
│   └── index.ts
├── tests/unit/
│   ├── pipeline.test.ts         # 9 tests — severity logic, report builder
│   └── secret-scanner.test.ts   # 7 tests — pattern detection, edge cases
└── .github/workflows/ci.yml
```

---

## License

MIT

---

Built by [Quvantic](https://quvantic.com)
