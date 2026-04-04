import { PipelineReport, ScanResult, Severity } from './types';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function shouldFail(result: ScanResult, failOnSeverity: Severity): boolean {
  return result.findings.some(
    (f) => SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[failOnSeverity],
  );
}

export function buildReport(
  target: string,
  results: ScanResult[],
): PipelineReport {
  const allFindings = results.flatMap((r) => r.findings);

  return {
    timestamp: new Date().toISOString(),
    target,
    scanResults: results,
    summary: {
      totalFindings: allFindings.length,
      critical: allFindings.filter((f) => f.severity === 'critical').length,
      high: allFindings.filter((f) => f.severity === 'high').length,
      medium: allFindings.filter((f) => f.severity === 'medium').length,
      low: allFindings.filter((f) => f.severity === 'low').length,
      info: allFindings.filter((f) => f.severity === 'info').length,
      scansPassed: results.filter((r) => r.passed).length,
      scansFailed: results.filter((r) => !r.passed).length,
    },
    overallPassed: results.every((r) => r.passed),
  };
}

export function severityAtOrAbove(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[severity] <= SEVERITY_ORDER[threshold];
}
