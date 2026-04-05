import { describe, it, expect, vi, afterEach } from 'vitest';

// We need to mock execSync before importing the scanner
vi.mock('child_process', () => ({
  execSync: vi.fn(),
}));

import { execSync } from 'child_process';
import { runDependencyScan } from '../../src/scanners/dependency.scanner';
import { ScannerConfig } from '../../src/core/types';

const mockedExecSync = vi.mocked(execSync);

afterEach(() => {
  vi.clearAllMocks();
});

const config: ScannerConfig = { failOnSeverity: 'high' };

describe('runDependencyScan', () => {
  it('should parse npm audit output with vulnerabilities', () => {
    const auditOutput = JSON.stringify({
      vulnerabilities: {
        lodash: {
          name: 'lodash',
          severity: 'high',
          title: 'Prototype Pollution',
          url: 'https://github.com/advisories/GHSA-1234',
          range: '<4.17.21',
          fixAvailable: { name: 'lodash', version: '4.17.21' },
        },
        minimist: {
          name: 'minimist',
          severity: 'critical',
          title: 'Prototype Pollution in minimist',
          url: 'https://github.com/advisories/GHSA-5678',
          range: '<1.2.6',
          fixAvailable: true,
        },
      },
    });

    // npm audit exits non-zero when vulns found
    const error = new Error('npm audit found vulns') as Error & { stdout: string };
    error.stdout = auditOutput;
    mockedExecSync.mockImplementation(() => {
      throw error;
    });

    const result = runDependencyScan('/tmp/test-project', config);

    expect(result.scanType).toBe('dependency');
    expect(result.scanner).toBe('npm audit');
    expect(result.findings).toHaveLength(2);
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].title).toContain('lodash');
    expect(result.findings[0].remediation).toContain('4.17.21');
    expect(result.findings[1].severity).toBe('critical');
    expect(result.findings[1].remediation).toBe('Run npm audit fix');
    expect(result.passed).toBe(false); // has high+ findings
  });

  it('should pass when no vulnerabilities found', () => {
    mockedExecSync.mockReturnValue(JSON.stringify({ vulnerabilities: {} }) as unknown as Buffer);

    const result = runDependencyScan('/tmp/clean-project', config);

    expect(result.findings).toHaveLength(0);
    expect(result.passed).toBe(true);
  });

  it('should handle fix not available', () => {
    const auditOutput = JSON.stringify({
      vulnerabilities: {
        'old-pkg': {
          name: 'old-pkg',
          severity: 'moderate',
          title: 'Known vulnerability',
          url: 'https://example.com',
          range: '*',
          fixAvailable: false,
        },
      },
    });

    mockedExecSync.mockReturnValue(auditOutput as unknown as Buffer);

    const result = runDependencyScan('/tmp/test', config);

    expect(result.findings[0].remediation).toContain('replacing');
    expect(result.passed).toBe(true); // moderate < high threshold
  });

  it('should handle malformed audit output', () => {
    const error = new Error('npm error') as Error & { stdout: string };
    error.stdout = 'not json at all';
    mockedExecSync.mockImplementation(() => {
      throw error;
    });

    const result = runDependencyScan('/tmp/test', config);

    expect(result.findings).toHaveLength(0);
    expect(result.passed).toBe(true);
  });

  it('should map npm severity levels correctly', () => {
    const auditOutput = JSON.stringify({
      vulnerabilities: {
        a: { name: 'a', severity: 'critical', title: 'A', url: '', range: '', fixAvailable: false },
        b: { name: 'b', severity: 'high', title: 'B', url: '', range: '', fixAvailable: false },
        c: { name: 'c', severity: 'moderate', title: 'C', url: '', range: '', fixAvailable: false },
        d: { name: 'd', severity: 'low', title: 'D', url: '', range: '', fixAvailable: false },
        e: { name: 'e', severity: 'unknown', title: 'E', url: '', range: '', fixAvailable: false },
      },
    });

    mockedExecSync.mockReturnValue(auditOutput as unknown as Buffer);
    const result = runDependencyScan('/tmp/test', { failOnSeverity: 'info' });

    const severities = result.findings.map((f) => f.severity);
    expect(severities).toContain('critical');
    expect(severities).toContain('high');
    expect(severities).toContain('medium');
    expect(severities).toContain('low');
    expect(severities).toContain('info');
  });
});
