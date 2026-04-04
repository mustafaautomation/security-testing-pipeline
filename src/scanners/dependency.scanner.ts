import { execSync } from 'child_process';
import { Finding, ScanResult, ScannerConfig } from '../core/types';
import { shouldFail } from '../core/pipeline';

interface NpmAuditVuln {
  name: string;
  severity: string;
  title: string;
  url: string;
  range: string;
  fixAvailable: boolean | { name: string; version: string };
}

interface NpmAuditOutput {
  vulnerabilities: Record<string, NpmAuditVuln>;
}

function mapSeverity(npmSev: string): Finding['severity'] {
  switch (npmSev) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info';
  }
}

export function runDependencyScan(target: string, config: ScannerConfig): ScanResult {
  const start = Date.now();
  const findings: Finding[] = [];

  try {
    const output = execSync('npm audit --json', {
      encoding: 'utf-8',
      cwd: target,
      timeout: 120000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    parseNpmAudit(output, findings);
  } catch (err) {
    const error = err as { stdout?: string };
    // npm audit exits non-zero when vulnerabilities found
    if (error.stdout) {
      parseNpmAudit(error.stdout, findings);
    }
  }

  const result: ScanResult = {
    scanType: 'dependency',
    scanner: 'npm audit',
    timestamp: new Date().toISOString(),
    duration: Date.now() - start,
    findings,
    passed: true,
  };

  result.passed = !shouldFail(result, config.failOnSeverity);
  return result;
}

function parseNpmAudit(output: string, findings: Finding[]): void {
  try {
    const parsed: NpmAuditOutput = JSON.parse(output);
    for (const [pkg, vuln] of Object.entries(parsed.vulnerabilities || {})) {
      const fixInfo =
        typeof vuln.fixAvailable === 'object'
          ? `Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
          : vuln.fixAvailable
            ? 'Run npm audit fix'
            : 'No fix available — consider replacing the package';

      findings.push({
        id: `npm-${pkg}`,
        title: `${vuln.title} in ${pkg}`,
        severity: mapSeverity(vuln.severity),
        scanType: 'dependency',
        description: `Vulnerable versions: ${vuln.range}`,
        remediation: fixInfo,
        reference: vuln.url,
      });
    }
  } catch {
    // Malformed output
  }
}
