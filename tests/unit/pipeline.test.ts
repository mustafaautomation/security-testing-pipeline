import { describe, it, expect } from 'vitest';
import { buildReport, shouldFail, severityAtOrAbove } from '../../src/core/pipeline';
import { ScanResult, Finding } from '../../src/core/types';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'test-finding',
    title: 'Test Finding',
    severity: 'medium',
    scanType: 'sast',
    description: 'A test finding',
    remediation: 'Fix it',
    ...overrides,
  };
}

function makeScanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    scanType: 'sast',
    scanner: 'Test Scanner',
    timestamp: new Date().toISOString(),
    duration: 100,
    findings: [],
    passed: true,
    ...overrides,
  };
}

describe('shouldFail', () => {
  it('should fail when finding severity meets threshold', () => {
    const result = makeScanResult({
      findings: [makeFinding({ severity: 'high' })],
    });
    expect(shouldFail(result, 'high')).toBe(true);
  });

  it('should fail when finding severity exceeds threshold', () => {
    const result = makeScanResult({
      findings: [makeFinding({ severity: 'critical' })],
    });
    expect(shouldFail(result, 'high')).toBe(true);
  });

  it('should pass when finding severity is below threshold', () => {
    const result = makeScanResult({
      findings: [makeFinding({ severity: 'low' })],
    });
    expect(shouldFail(result, 'high')).toBe(false);
  });

  it('should pass with no findings', () => {
    const result = makeScanResult({ findings: [] });
    expect(shouldFail(result, 'high')).toBe(false);
  });
});

describe('severityAtOrAbove', () => {
  it('critical is at or above high', () => {
    expect(severityAtOrAbove('critical', 'high')).toBe(true);
  });

  it('low is not at or above high', () => {
    expect(severityAtOrAbove('low', 'high')).toBe(false);
  });

  it('same severity matches', () => {
    expect(severityAtOrAbove('medium', 'medium')).toBe(true);
  });
});

describe('buildReport', () => {
  it('should aggregate findings from multiple scans', () => {
    const results = [
      makeScanResult({
        scanType: 'sast',
        findings: [makeFinding({ severity: 'high' }), makeFinding({ severity: 'medium' })],
        passed: false,
      }),
      makeScanResult({
        scanType: 'secret',
        scanner: 'Secret Scanner',
        findings: [makeFinding({ severity: 'critical', scanType: 'secret' })],
        passed: false,
      }),
      makeScanResult({
        scanType: 'dependency',
        scanner: 'npm audit',
        findings: [],
        passed: true,
      }),
    ];

    const report = buildReport('.', results);

    expect(report.summary.totalFindings).toBe(3);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.high).toBe(1);
    expect(report.summary.medium).toBe(1);
    expect(report.summary.scansPassed).toBe(1);
    expect(report.summary.scansFailed).toBe(2);
    expect(report.overallPassed).toBe(false);
  });

  it('should pass when all scans pass', () => {
    const results = [
      makeScanResult({ passed: true }),
      makeScanResult({ passed: true }),
    ];

    const report = buildReport('.', results);
    expect(report.overallPassed).toBe(true);
  });

  it('should handle empty results', () => {
    const report = buildReport('.', []);
    expect(report.summary.totalFindings).toBe(0);
    expect(report.overallPassed).toBe(true);
  });
});
