export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanType = 'sast' | 'dependency' | 'secret' | 'dast';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  scanType: ScanType;
  file?: string;
  line?: number;
  description: string;
  remediation: string;
  cwe?: string;
  reference?: string;
}

export interface ScanResult {
  scanType: ScanType;
  scanner: string;
  timestamp: string;
  duration: number;
  findings: Finding[];
  passed: boolean;
}

export interface PipelineReport {
  timestamp: string;
  target: string;
  scanResults: ScanResult[];
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    scansPassed: number;
    scansFailed: number;
  };
  overallPassed: boolean;
}

export interface ScannerConfig {
  enabled: boolean;
  failOnSeverity: Severity;
}

export interface PipelineConfig {
  target: string;
  sast: ScannerConfig;
  dependency: ScannerConfig;
  secret: ScannerConfig;
  dast: ScannerConfig & { targetUrl?: string };
}

export const DEFAULT_CONFIG: PipelineConfig = {
  target: '.',
  sast: { enabled: true, failOnSeverity: 'high' },
  dependency: { enabled: true, failOnSeverity: 'critical' },
  secret: { enabled: true, failOnSeverity: 'high' },
  dast: { enabled: false, failOnSeverity: 'high' },
};
