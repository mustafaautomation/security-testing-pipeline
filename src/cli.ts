#!/usr/bin/env node

import { Command } from 'commander';
import { DEFAULT_CONFIG, PipelineConfig, ScanResult, Severity } from './core/types';
import { buildReport } from './core/pipeline';
import { runSecretScan } from './scanners/secret.scanner';
import { runDependencyScan } from './scanners/dependency.scanner';
import { runSastScan } from './scanners/sast.scanner';
import { printReport } from './reporters/console.reporter';
import { generateJsonReport } from './reporters/json.reporter';

const program = new Command();

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version } = require('../package.json');
program.name('sec-scan').description('Security scanning pipeline CLI').version(version);

program
  .command('scan')
  .description('Run security scans on a target directory')
  .argument('[target]', 'Target directory to scan', '.')
  .option('--sast', 'Run SAST scan (requires Semgrep)')
  .option('--deps', 'Run dependency audit (requires npm)')
  .option('--secrets', 'Run secret detection')
  .option('--all', 'Run all enabled scans')
  .option('--fail-on <severity>', 'Fail on severity: critical, high, medium, low', 'high')
  .option('--json <path>', 'Output JSON report')
  .action((target: string, options) => {
    const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
    if (!VALID_SEVERITIES.includes(options.failOn)) {
      console.error(`Invalid severity: "${options.failOn}". Valid: ${VALID_SEVERITIES.join(', ')}`);
      process.exit(1);
    }

    const hasSpecificFlag = options.sast || options.deps || options.secrets;
    const runAll = options.all || !hasSpecificFlag;

    const config: PipelineConfig = {
      ...DEFAULT_CONFIG,
      target,
      sast: { enabled: runAll || !!options.sast, failOnSeverity: options.failOn as Severity },
      dependency: {
        enabled: runAll || !!options.deps,
        failOnSeverity: options.failOn as Severity,
      },
      secret: {
        enabled: runAll || !!options.secrets,
        failOnSeverity: options.failOn as Severity,
      },
    };

    const results: ScanResult[] = [];

    if (config.secret.enabled) {
      results.push(runSecretScan(target, config.secret));
    }
    if (config.dependency.enabled) {
      results.push(runDependencyScan(target, config.dependency));
    }
    if (config.sast.enabled) {
      results.push(runSastScan(target, config.sast));
    }

    const report = buildReport(target, results);
    printReport(report);

    if (options.json) {
      generateJsonReport(report, options.json);
      console.log(`JSON report: ${options.json}`);
    }

    if (!report.overallPassed) {
      process.exit(1);
    }
  });

program.parse();
