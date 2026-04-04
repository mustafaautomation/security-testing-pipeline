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

program
  .name('sec-scan')
  .description('Security scanning pipeline CLI')
  .version('1.0.0');

program
  .command('scan')
  .description('Run security scans on a target directory')
  .argument('[target]', 'Target directory to scan', '.')
  .option('--sast', 'Run SAST scan (requires Semgrep)')
  .option('--deps', 'Run dependency audit (requires npm)')
  .option('--secrets', 'Run secret detection')
  .option('--all', 'Run all enabled scans', true)
  .option('--fail-on <severity>', 'Fail on severity: critical, high, medium, low', 'high')
  .option('--json <path>', 'Output JSON report')
  .action((target: string, options) => {
    const config: PipelineConfig = {
      ...DEFAULT_CONFIG,
      target,
      sast: { enabled: options.all || options.sast, failOnSeverity: options.failOn as Severity },
      dependency: { enabled: options.all || options.deps, failOnSeverity: options.failOn as Severity },
      secret: { enabled: options.all || options.secrets, failOnSeverity: options.failOn as Severity },
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
