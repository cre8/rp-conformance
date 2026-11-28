// Class RP_TB: the test book of the Relying Party (rp-test-catalogue.md section 5.4). Requirements without a standard
// interface, checked by inspection; every run reports them as REVIEW with their method.
import { defineTestBookItem, relevancy, type TestBookItem } from '@eudi-pcaf/core';

export const testBook: TestBookItem[] = [
  {
    id: 'RP_TB_001',
    objective:
      'Unique elements (salts, digests, signatures, status index and URI, KB-JWT, timestamps) are discarded once no longer needed and not passed to the relying service or third parties.',
    method: 'Inspect what the RP forwards (API, webhooks, logs) and stores after a transaction.',
    references: ['[ARF] Annex 2, OIA_16, ISSU_35'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_002',
    objective: 'The PID portrait is not retained or transferred without a legal basis.',
    method: 'Inspect storage and forwarding after a portrait request.',
    references: ['[ARF] Annex 2, PID_03a', '[CIR 2024/2977]'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_003',
    objective: 'If revocation is not checked, or accepted without reliable status, a risk analysis exists and matches ICS-05 / ICS-06.',
    method: 'Document review.',
    references: ['[ARF] Annex 2, VCR_13, VCR_14'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_004',
    objective: 'Status lists are distributed to RP Instances instead of being fetched per presentation.',
    method: 'Architecture review, `RP_PP_IA_Supportive_002`.',
    references: ['[ARF] Annex 2, VCR_15'],
    relevancy: relevancy.specificOptional,
  },
  {
    id: 'RP_TB_005',
    objective: 'Cross-device redirect flows have documented and implemented mitigations.',
    method: 'Document review and walkthrough.',
    references: ['[ARF] Annex 2, OIA_08d', '[ARF] section 4.4.3.1'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_006',
    objective: 'Configured algorithms are limited to ECCG ACM v2.0.',
    method: 'Configuration review.',
    references: ['[ARF] Annex 2, OIA_03'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_007',
    objective:
      'Data deletion requests arrive through the channel in the registration certificate, the requester is authenticated, and the TS7 interface is supported.',
    method: 'Walkthrough.',
    references: ['[ARF] Annex 2, DATA_DLT_07, DATA_DLT_08, RPRC_11'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_008',
    objective: 'Registration data is kept current and registration certificates reach all RP Instances.',
    method: 'Process review.',
    references: ['[ARF] Annex 2, Reg_08, RPRC_10'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_009',
    objective: 'Trust anchors are stored per category so they cannot be mixed up.',
    method: 'Configuration review; complements `RP_WS_SM_TrustMechanisms`.',
    references: ['[ARF] Annex 2, OIA_15 note'],
    relevancy: relevancy.specificRequired,
  },
  {
    id: 'RP_TB_010',
    objective: 'Pseudonym verification (deferred until RP pseudonym support is in scope).',
    method: 'None yet: the catalogue defines no method until RP pseudonym support is in scope.',
    references: ['[ARF] Annex 2, PA_10, PA_11, PA_12, PA_13, PA_15'],
    relevancy: relevancy.specificOptional,
  },
].map(defineTestBookItem);
