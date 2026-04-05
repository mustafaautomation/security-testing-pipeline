import { describe, it, expect } from 'vitest';
import { shouldFail, buildReport, severityAtOrAbove } from '../../src/core/pipeline';
import { ScanResult, Finding } from '../../src/core/types';

describe('severityAtOrAbove', () => {
  it('should return true for same severity', () => {
    expect(severityAtOrAbove('high', 'high')).toBe(true);
  });

  it('should return true for higher severity', () => {
    expect(severityAtOrAbove('critical', 'high')).toBe(true);
  });

  it('should return false for lower severity', () => {
    expect(severityAtOrAbove('low', 'high')).toBe(false);
  });

  it('should handle all severity comparisons', () => {
    // critical > high > medium > low > info
    expect(severityAtOrAbove('critical', 'info')).toBe(true);
    expect(severityAtOrAbove('info', 'critical')).toBe(false);
    expect(severityAtOrAbove('medium', 'medium')).toBe(true);
    expect(severityAtOrAbove('low', 'medium')).toBe(false);
  });
});

describe('buildReport', () => {
  const makeResult = (type: string, findings: Finding[], passed: boolean): ScanResult => ({
    scanType: type as ScanResult['scanType'],
    scanner: `${type} scanner`,
    timestamp: new Date().toISOString(),
    duration: 100,
    findings,
    passed,
  });

  it('should build report with correct summary', () => {
    const findings: Finding[] = [
      {
        id: '1',
        title: 'A',
        severity: 'critical',
        scanType: 'secret',
        description: '',
        remediation: '',
      },
      {
        id: '2',
        title: 'B',
        severity: 'high',
        scanType: 'secret',
        description: '',
        remediation: '',
      },
      {
        id: '3',
        title: 'C',
        severity: 'medium',
        scanType: 'sast',
        description: '',
        remediation: '',
      },
      {
        id: '4',
        title: 'D',
        severity: 'low',
        scanType: 'dependency',
        description: '',
        remediation: '',
      },
      {
        id: '5',
        title: 'E',
        severity: 'info',
        scanType: 'dependency',
        description: '',
        remediation: '',
      },
    ];

    const results = [
      makeResult('secret', findings.slice(0, 2), false),
      makeResult('sast', findings.slice(2, 3), true),
      makeResult('dependency', findings.slice(3), true),
    ];

    const report = buildReport('/tmp/target', results);

    expect(report.target).toBe('/tmp/target');
    expect(report.summary.totalFindings).toBe(5);
    expect(report.summary.critical).toBe(1);
    expect(report.summary.high).toBe(1);
    expect(report.summary.medium).toBe(1);
    expect(report.summary.low).toBe(1);
    expect(report.summary.info).toBe(1);
    expect(report.summary.scansPassed).toBe(2);
    expect(report.summary.scansFailed).toBe(1);
    expect(report.overallPassed).toBe(false);
  });

  it('should pass when all scans pass', () => {
    const results = [makeResult('secret', [], true), makeResult('dependency', [], true)];

    const report = buildReport('/tmp/clean', results);

    expect(report.overallPassed).toBe(true);
    expect(report.summary.totalFindings).toBe(0);
    expect(report.summary.scansPassed).toBe(2);
    expect(report.summary.scansFailed).toBe(0);
  });

  it('should handle empty results', () => {
    const report = buildReport('/tmp/nothing', []);

    expect(report.overallPassed).toBe(true);
    expect(report.summary.totalFindings).toBe(0);
  });

  it('should include timestamp', () => {
    const report = buildReport('/tmp/ts', []);
    expect(report.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}/);
  });
});

describe('shouldFail with different thresholds', () => {
  const makeScan = (severity: Finding['severity']): ScanResult => ({
    scanType: 'secret',
    scanner: 'test',
    timestamp: '',
    duration: 0,
    findings: [
      { id: '1', title: 'T', severity, scanType: 'secret', description: '', remediation: '' },
    ],
    passed: true,
  });

  it('should fail critical finding with critical threshold', () => {
    expect(shouldFail(makeScan('critical'), 'critical')).toBe(true);
  });

  it('should not fail medium finding with high threshold', () => {
    expect(shouldFail(makeScan('medium'), 'high')).toBe(false);
  });

  it('should fail any finding with info threshold', () => {
    expect(shouldFail(makeScan('info'), 'info')).toBe(true);
    expect(shouldFail(makeScan('low'), 'info')).toBe(true);
  });

  it('should not fail empty scan', () => {
    const emptyScan: ScanResult = {
      scanType: 'secret',
      scanner: 'test',
      timestamp: '',
      duration: 0,
      findings: [],
      passed: true,
    };
    expect(shouldFail(emptyScan, 'info')).toBe(false);
  });
});
