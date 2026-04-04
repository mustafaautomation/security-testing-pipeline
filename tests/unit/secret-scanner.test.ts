import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { runSecretScan } from '../../src/scanners/secret.scanner';

const TMP = path.join(__dirname, '.tmp-secrets');

describe('Secret Scanner', () => {
  beforeEach(() => {
    fs.mkdirSync(TMP, { recursive: true });
  });

  afterEach(() => {
    if (fs.existsSync(TMP)) fs.rmSync(TMP, { recursive: true });
  });

  it('should detect AWS access key', () => {
    fs.writeFileSync(path.join(TMP, 'config.ts'), 'const key = "AKIAIOSFODNN7EXAMPLE";');
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].title).toContain('AWS Access Key');
    expect(result.findings[0].severity).toBe('critical');
  });

  it('should detect GitHub token', () => {
    fs.writeFileSync(
      path.join(TMP, 'env.ts'),
      'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";',
    );
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.findings.some((f) => f.title.includes('GitHub Token'))).toBe(true);
  });

  it('should detect private key header', () => {
    fs.writeFileSync(
      path.join(TMP, 'key.pem'),
      '-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----',
    );
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.findings.some((f) => f.title.includes('Private Key'))).toBe(true);
  });

  it('should detect password in variable', () => {
    fs.writeFileSync(path.join(TMP, 'db.ts'), 'const password = "SuperSecret123!";');
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.findings.some((f) => f.title.includes('Password'))).toBe(true);
  });

  it('should return no findings for clean files', () => {
    fs.writeFileSync(path.join(TMP, 'clean.ts'), 'const x = 42;\nconsole.log("hello");');
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.findings).toHaveLength(0);
    expect(result.passed).toBe(true);
  });

  it('should skip binary file extensions', () => {
    fs.writeFileSync(path.join(TMP, 'image.png'), 'AKIAIOSFODNN7EXAMPLE');
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.findings).toHaveLength(0);
  });

  it('should mark as failed when critical finding and failOn is high', () => {
    fs.writeFileSync(path.join(TMP, 'leak.ts'), 'const key = "AKIAIOSFODNN7EXAMPLE";');
    const result = runSecretScan(TMP, { enabled: true, failOnSeverity: 'high' });
    expect(result.passed).toBe(false);
  });
});
