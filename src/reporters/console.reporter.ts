import { PipelineReport, Severity } from '../core/types';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';

const SEV_COLORS: Record<Severity, string> = {
  critical: RED,
  high: MAGENTA,
  medium: YELLOW,
  low: DIM,
  info: DIM,
};

export function printReport(report: PipelineReport): void {
  const statusIcon = report.overallPassed ? `${GREEN}PASSED` : `${RED}FAILED`;

  console.log();
  console.log(`${BOLD}${CYAN}Security Scan Report${RESET}`);
  console.log(`${DIM}${report.timestamp}${RESET}`);
  console.log();

  console.log(`  ${BOLD}Status:${RESET} ${statusIcon}${RESET}`);
  console.log(`  ${BOLD}Target:${RESET} ${report.target}`);
  console.log(
    `  ${BOLD}Findings:${RESET} ${report.summary.totalFindings}  ` +
      `${RED}${report.summary.critical} critical${RESET}  ` +
      `${MAGENTA}${report.summary.high} high${RESET}  ` +
      `${YELLOW}${report.summary.medium} medium${RESET}  ` +
      `${DIM}${report.summary.low} low${RESET}`,
  );
  console.log();

  for (const scan of report.scanResults) {
    const icon = scan.passed ? `${GREEN}✓` : `${RED}✗`;
    console.log(
      `  ${icon}${RESET} ${BOLD}${scan.scanner}${RESET} (${scan.scanType})  ` +
        `${DIM}${scan.findings.length} findings · ${scan.duration}ms${RESET}`,
    );

    for (const finding of scan.findings.slice(0, 5)) {
      const color = SEV_COLORS[finding.severity];
      const location = finding.file ? ` ${DIM}${finding.file}:${finding.line || ''}${RESET}` : '';
      console.log(`    ${color}[${finding.severity}]${RESET} ${finding.title}${location}`);
    }

    if (scan.findings.length > 5) {
      console.log(`    ${DIM}... and ${scan.findings.length - 5} more${RESET}`);
    }
  }

  console.log();
}
