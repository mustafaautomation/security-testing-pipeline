import { describe, it, expect, vi } from 'vitest';
import fs from 'fs';
import { printReport } from '../../src/reporters/console.reporter';
import { generateJsonReport } from '../../src/reporters/json.reporter';
import { PipelineReport } from '../../src/core/types';

const mockReport: PipelineReport = {
  timestamp: '2026-04-06T10:00:00Z',
  target: '/tmp/test-project',
  scanResults: [
    {
      scanType: 'secret',
      scanner: 'Built-in Secret Scanner',
      timestamp: '2026-04-06T10:00:00Z',
      duration: 150,
      findings: [
        {
          id: 'secret-aws-key',
          title: 'AWS Access Key detected',
          severity: 'critical',
          scanType: 'secret',
          file: 'src/config.ts',
          line: 15,
          description: 'Potential AWS Access Key found',
          remediation: 'Remove and rotate',
          cwe: 'CWE-798',
        },
        {
          id: 'secret-api-key',
          title: 'Generic API Key detected',
          severity: 'high',
          scanType: 'secret',
          file: 'src/utils.ts',
          line: 42,
          description: 'Potential API key found',
          remediation: 'Use env vars',
          cwe: 'CWE-798',
        },
      ],
      passed: false,
    },
    {
      scanType: 'dependency',
      scanner: 'npm audit',
      timestamp: '2026-04-06T10:00:00Z',
      duration: 2000,
      findings: [],
      passed: true,
    },
  ],
  summary: {
    totalFindings: 2,
    critical: 1,
    high: 1,
    medium: 0,
    low: 0,
    info: 0,
    scansPassed: 1,
    scansFailed: 1,
  },
  overallPassed: false,
};

describe('Console reporter', () => {
  it('should print report without errors', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    printReport(mockReport);

    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('Security Scan Report');
    expect(output).toContain('FAILED');
    expect(output).toContain('1 critical');
    expect(output).toContain('1 high');
    expect(output).toContain('AWS Access Key');
    expect(output).toContain('npm audit');

    spy.mockRestore();
  });

  it('should print PASSED for clean report', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const cleanReport: PipelineReport = {
      ...mockReport,
      overallPassed: true,
      summary: {
        ...mockReport.summary,
        totalFindings: 0,
        critical: 0,
        high: 0,
        scansFailed: 0,
        scansPassed: 2,
      },
      scanResults: mockReport.scanResults.map((s) => ({ ...s, findings: [], passed: true })),
    };

    printReport(cleanReport);

    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('PASSED');

    spy.mockRestore();
  });

  it('should truncate findings beyond 5', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const manyFindings: PipelineReport = {
      ...mockReport,
      scanResults: [
        {
          ...mockReport.scanResults[0],
          findings: Array.from({ length: 8 }, (_, i) => ({
            id: `finding-${i}`,
            title: `Finding ${i}`,
            severity: 'medium' as const,
            scanType: 'secret' as const,
            description: 'test',
            remediation: 'fix it',
          })),
        },
      ],
    };

    printReport(manyFindings);

    const output = spy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('and 3 more');

    spy.mockRestore();
  });
});

describe('JSON reporter', () => {
  it('should write report to file', () => {
    const outputPath = '/tmp/test-security-report.json';

    generateJsonReport(mockReport, outputPath);

    expect(fs.existsSync(outputPath)).toBe(true);
    const content = JSON.parse(fs.readFileSync(outputPath, 'utf-8'));
    expect(content.target).toBe('/tmp/test-project');
    expect(content.summary.totalFindings).toBe(2);
    expect(content.overallPassed).toBe(false);

    // Cleanup
    fs.unlinkSync(outputPath);
  });

  it('should create directory if it does not exist', () => {
    const outputPath = '/tmp/test-sec-reports-nested/sub/report.json';

    generateJsonReport(mockReport, outputPath);

    expect(fs.existsSync(outputPath)).toBe(true);

    // Cleanup
    fs.unlinkSync(outputPath);
    fs.rmdirSync('/tmp/test-sec-reports-nested/sub');
    fs.rmdirSync('/tmp/test-sec-reports-nested');
  });
});
