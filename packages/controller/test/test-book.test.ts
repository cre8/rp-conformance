import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DOMParser } from '@xmldom/xmldom';
import { defineTestBookItem, relevancy } from '@eudi-pcaf/core';
import { definitions, testBook } from '@eudi-pcaf/definitions';
import { describe, expect, it } from 'vitest';
import { junitXml } from '../src/junit';
import { runOutcome } from '../src/known-findings';
import { type RunReport, selectTestBook, selectTestCases, type TestBookRecord, type TestCaseRecord } from '../src/runner';
import { writeSummary } from '../src/summary';

const record = (testCase: string, verdict: TestCaseRecord['verdict']): TestCaseRecord => ({ testCase, flow: 'redirect', verdict, control: null, steps: [] });

const review = (id: string, method = 'Document review.'): TestBookRecord => ({
  id,
  objective: `Objective of ${id} | with a pipe`,
  method,
  references: ['[ARF] Annex 2, VCR_13'],
  relevancy: relevancy.specificRequired,
  verdict: 'REVIEW',
});

const report = (results: TestCaseRecord[], items: TestBookRecord[]): RunReport => ({
  run: {
    id: 'r1',
    startedAt: '2026-11-19T00:00:00.000Z',
    adapter: 'reference',
    flows: ['redirect'],
    ics: { items: {} },
    harness: { name: 'eudi-pcaf', phase: 4, node: 'v22', libraries: { '@openid4vc/openid4vp': '0', playwright: '0' } },
    environment: { namespace: 'r1', statusProvider: '', trustInfrastructure: '', trustLists: [], listOfTrustedLists: { url: '', pointers: [] } },
    summary: { PASS: results.length },
  },
  results,
  testBook: items,
});

describe('test book definitions', () => {
  it('are the 10 RP_TB items of the catalogue, each with a method', () => {
    expect(testBook.map((item) => item.id)).toEqual(Array.from({ length: 10 }, (_, i) => `RP_TB_${String(i + 1).padStart(3, '0')}`));
    for (const item of testBook) expect(item.method.length).toBeGreaterThan(0);
    expect(definitions.some((d) => d.id.startsWith('RP_TB'))).toBe(false);
  });

  it('rejects an ID outside a test book class and an item without a method', () => {
    const item = { id: 'RP_TB_011', objective: 'x', method: 'Walkthrough.', references: [], relevancy: relevancy.specificRequired };
    expect(defineTestBookItem(item)).toBe(item);
    expect(defineTestBookItem({ ...item, id: 'PP_TB_014' }).id).toBe('PP_TB_014');
    expect(() => defineTestBookItem({ ...item, id: 'RP_WS_TB_001' })).toThrow('not a test book item ID');
    expect(() => defineTestBookItem({ ...item, method: ' ' })).toThrow('needs an objective and a method');
  });
});

describe('test book selection', () => {
  it('selects every item without --only, and the matching ones with it', () => {
    expect(selectTestBook(testBook)).toHaveLength(10);
    expect(selectTestBook(testBook, ['RP_TB_00*']).map((i) => i.id)).toHaveLength(9);
    expect(selectTestBook(testBook, ['RP_WS_IA_MainInteraction_001a'])).toEqual([]);
  });

  it('accepts --only that names test book items only, and still refuses one that matches nothing', () => {
    expect(selectTestCases(definitions, ['RP_TB_003'], testBook)).toEqual([]);
    expect(() => selectTestCases(definitions, ['RP_XX_*'], testBook)).toThrow('no executable test case matches');
  });
});

describe('test book in the reports', () => {
  const run = report([record('RP_WS_IA_MainInteraction_001a', 'PASS')], [review('RP_TB_003'), review('RP_TB_006', 'Configuration review.')]);

  it('summary.md lists the items as REVIEW with their method in a section of their own', async () => {
    const path = join(await mkdtemp(join(tmpdir(), 'tb-')), 'summary.md');
    await writeSummary(run, path);
    const text = await readFile(path, 'utf8');
    const section = text.slice(text.indexOf('## Test book'));
    expect(text.indexOf('## Test book')).toBeGreaterThan(text.indexOf('| RP_WS_IA_MainInteraction_001a |'));
    expect(section).toContain('| RP_TB_003 | REVIEW | Objective of RP_TB_003 \\| with a pipe | Document review. |');
    expect(section).toContain('| RP_TB_006 | REVIEW | Objective of RP_TB_006 \\| with a pipe | Configuration review. |');
  });

  it('summary.md has no test book section when no item is selected', async () => {
    const path = join(await mkdtemp(join(tmpdir(), 'tb-')), 'summary.md');
    await writeSummary(report([record('RP_WS_IA_MainInteraction_001a', 'PASS')], []), path);
    expect(await readFile(path, 'utf8')).not.toContain('## Test book');
  });

  it('JUnit XML has a test book suite whose items are skipped as REVIEW with their method, not errors', () => {
    const doc = new DOMParser().parseFromString(junitXml(run), 'text/xml');
    const root = doc.getElementsByTagName('testsuites')[0];
    expect([root.getAttribute('tests'), root.getAttribute('errors'), root.getAttribute('skipped')]).toEqual(['3', '0', '2']);
    const suites = Array.from(doc.getElementsByTagName('testsuite'));
    expect(suites.map((s) => s.getAttribute('name'))).toEqual(['reference redirect', 'reference test book']);
    const book = suites[1];
    expect([book.getAttribute('tests'), book.getAttribute('failures'), book.getAttribute('errors'), book.getAttribute('skipped')]).toEqual(['2', '0', '0', '2']);
    const cases = Array.from(book.getElementsByTagName('testcase'));
    expect(cases.map((c) => [c.getAttribute('classname'), c.getAttribute('name')])).toEqual([
      ['RP_TB', 'RP_TB_003'],
      ['RP_TB', 'RP_TB_006'],
    ]);
    expect(cases[1].getElementsByTagName('skipped')[0].getAttribute('message')).toBe('REVIEW: Configuration review.');
    expect(cases[0].getElementsByTagName('system-out')[0].textContent).toContain('Method: Document review.');
  });
});

describe('exit code rule with known findings', () => {
  it('passes a run whose only REVIEW results are test book items', () => {
    const outcome = runOutcome(report([record('RP_WS_IA_MainInteraction_001a', 'PASS')], [review('RP_TB_001'), review('RP_TB_002')]), []);
    expect(outcome).toEqual({ ok: true, unexpected: [], known: [], resolved: [] });
  });

  it('still fails a run in which an executable test case is REVIEW', () => {
    const outcome = runOutcome(report([record('RP_WS_SM_Revocation_014a', 'REVIEW')], [review('RP_TB_001')]), []);
    expect(outcome.ok).toBe(false);
    expect(outcome.unexpected).toEqual(['RP_WS_SM_Revocation_014a [redirect] REVIEW']);
  });
});
