import type { CheckId, CheckResult, CheckStatus } from '@rp-conformance/core';

/**
 * `first-failure`: stop at the first failed check, as a Relying Party does (no status list is fetched for an invalid
 * credential). `all`: evaluate every check whose prerequisites passed, so the self-validation can prove that a fault
 * fails exactly one check (harness design section 7).
 */
export type ValidationMode = 'first-failure' | 'all';

export interface ValidationResult {
  valid: boolean;
  /** Every check evaluated, in order. */
  checks: CheckResult[];
  /** The first failed check. */
  failed?: CheckId;
  /** Every failed check. */
  failures: CheckId[];
}

/** Thrown inside a check to fail it with a reason. */
export class CheckFailure extends Error {}

/** Returned by a check that does not apply. */
export class NotApplicable {
  constructor(readonly reason: string) {}
}

class Stop extends Error {}

export class CheckRecorder {
  readonly results: CheckResult[] = [];

  constructor(readonly mode: ValidationMode) {}

  statusOf(check: CheckId): CheckStatus | undefined {
    return this.results.find((r) => r.check === check)?.status;
  }

  passed(check: CheckId): boolean {
    return this.statusOf(check) === 'pass';
  }

  get failures(): CheckId[] {
    return this.results.filter((r) => r.status === 'fail').map((r) => r.check);
  }

  record(check: CheckId, status: CheckStatus, detail?: string) {
    this.results.push({ check, status, ...(detail ? { detail } : {}) });
    if (status === 'fail' && this.mode === 'first-failure') throw new Stop(detail);
  }

  /**
   * Runs a check unless a check it requires did not pass (then `skip`). The function fails the check by throwing,
   * returns a detail on success, or `NotApplicable` for `skip`.
   */
  async run(check: CheckId, requires: CheckId[], fn: () => Promise<string | void | NotApplicable> | string | void | NotApplicable): Promise<boolean> {
    const missing = requires.filter((r) => !this.passed(r));
    if (missing.length) {
      this.record(check, 'skip', `requires ${missing.join(', ')}`);
      return false;
    }
    let outcome: string | void | NotApplicable;
    try {
      outcome = await fn();
    } catch (error) {
      if (error instanceof Stop) throw error;
      this.record(check, 'fail', (error as Error).message ?? String(error));
      return false;
    }
    if (outcome instanceof NotApplicable) {
      this.record(check, 'skip', outcome.reason);
      return false;
    }
    this.record(check, 'pass', outcome || undefined);
    return true;
  }

  /** Runs `body`; in `first-failure` mode it ends at the first failure. */
  async collect(body: () => Promise<void>): Promise<ValidationResult> {
    try {
      await body();
    } catch (error) {
      if (!(error instanceof Stop)) throw error;
    }
    const failures = this.failures;
    return { valid: failures.length === 0, checks: this.results, failed: failures[0], failures };
  }
}
