import fs from 'fs';
import path from 'path';
import { PipelineReport } from '../core/types';

export function generateJsonReport(report: PipelineReport, outputPath: string): void {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
}
