import fs from 'fs';
import path from 'path';
import { PipelineReport } from '../core/types';

export function generateJsonReport(report: PipelineReport, outputPath: string): void {
  try {
    const dir = path.dirname(outputPath);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
  } catch (err) {
    console.error(`Failed to write JSON report to ${outputPath}: ${(err as Error).message}`);
  }
}
