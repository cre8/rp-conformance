// The claims the adapter seeds are the suite's test subjects (core PID_TEST_SUBJECTS) in each format's names, with the
// ages and dates the PID derives at issuance.
import { PID_TEST_SUBJECTS, pidClaimsOf } from '@eudi-pcaf/core';
import { describe, expect, it } from 'vitest';
import { PID_SUBJECTS, pidClaimsFor } from '../src/index';

describe('seeded subjects', () => {
  it('PID_SUBJECTS are the suite subjects in SD-JWT VC names', () => {
    for (const subject of ['SUBJ-1', 'SUBJ-2'] as const) expect(PID_SUBJECTS[subject]).toEqual(pidClaimsOf(PID_TEST_SUBJECTS[subject], 'SD'));
  });

  it('derives ages and the issuance and expiry dates, the expiry rounded up to the hour', () => {
    const now = Date.parse('2026-11-20T23:30:00Z');
    const sd = pidClaimsFor('SUBJ-1', 'SD', 12 * 60 * 60, now);
    expect(sd).toMatchObject({ birthdate: '1964-08-12', age_equal_or_over: { '18': true }, age_in_years: 62, age_birth_year: 1964, date_of_issuance: '2026-11-20', date_of_expiry: '2026-11-21' });
    const md = pidClaimsFor('SUBJ-1', 'MD', 30 * 24 * 60 * 60, now);
    expect(md).toMatchObject({ birth_date: '1964-08-12', nationality: ['DE'], age_over_18: true, issuance_date: '2026-11-20', expiry_date: '2026-12-21' });
  });
});
