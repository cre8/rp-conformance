import type { DcqlQuery, DefaultQueryId } from '@rp-conformance/core';
import { PID_VCT } from './pid';

/**
 * The default DCQL queries (FCAF defaults, "Relying Party testing"). `default_query_pid` in SD-JWT VC format:
 * family name, given name and birth date, cryptographic holder binding required, no `trusted_authorities`.
 */
export const DEFAULT_QUERIES: Record<DefaultQueryId, DcqlQuery> = {
  default_query_pid: {
    credentials: [
      {
        id: 'pid',
        format: 'dc+sd-jwt',
        meta: { vct_values: [PID_VCT] },
        claims: [{ path: ['family_name'] }, { path: ['given_name'] }, { path: ['birthdate'] }],
        require_cryptographic_holder_binding: true,
      },
    ],
  },
};
