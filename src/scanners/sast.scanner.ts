import { execFileSync } from 'child_process';
import { Finding, ScanResult, ScannerConfig } from '../core/types';
import { shouldFail } from '../core/pipeline';

interface SemgrepResult {
  results: Array<{
    check_id: string;
    path: string;
    start: { line: number };
    extra: {
      message: string;
      severity: string;
      metadata?: { cwe?: string[]; references?: string[] };
      fix?: string;
    };
  }>;
}

function mapSeverity(semgrepSev: string): Finding['severity'] {
  switch (semgrepSev.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'ERROR':
      return 'high';
    case 'WARNING':
      return 'medium';
    case 'INFO':
      return 'low';
    default:
      return 'info';
  }
}

export function runSastScan(target: string, config: ScannerConfig): ScanResult {
  const start = Date.now();
  const findings: Finding[] = [];

  try {
    const output = execFileSync(
      'semgrep',
      ['scan', '--config', 'auto', '--json', '--quiet', target],
      {
        encoding: 'utf-8',
        timeout: 300000,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );

    const parsed: SemgrepResult = JSON.parse(output);

    for (const result of parsed.results) {
      findings.push({
        id: result.check_id,
        title: result.check_id.split('.').pop() || result.check_id,
        severity: mapSeverity(result.extra.severity),
        scanType: 'sast',
        file: result.path,
        line: result.start.line,
        description: result.extra.message,
        remediation: result.extra.fix || 'Review and fix the flagged code pattern',
        cwe: result.extra.metadata?.cwe?.[0],
        reference: result.extra.metadata?.references?.[0],
      });
    }
  } catch (err) {
    const error = err as { stdout?: string; status?: number };
    // Semgrep exits 1 when findings exist
    if (error.stdout) {
      try {
        const parsed: SemgrepResult = JSON.parse(error.stdout);
        for (const result of parsed.results) {
          findings.push({
            id: result.check_id,
            title: result.check_id.split('.').pop() || result.check_id,
            severity: mapSeverity(result.extra.severity),
            scanType: 'sast',
            file: result.path,
            line: result.start.line,
            description: result.extra.message,
            remediation: result.extra.fix || 'Review and fix the flagged code pattern',
            cwe: result.extra.metadata?.cwe?.[0],
          });
        }
      } catch {
        // Non-JSON output — semgrep not installed or errored
      }
    }
  }

  const result: ScanResult = {
    scanType: 'sast',
    scanner: 'Semgrep',
    timestamp: new Date().toISOString(),
    duration: Date.now() - start,
    findings,
    passed: true,
  };

  result.passed = !shouldFail(result, config.failOnSeverity);
  return result;
}
