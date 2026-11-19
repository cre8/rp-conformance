// RP_WS_SM_DeviceBinding: the presentation proves possession of the key the credential is bound to, with a KB-JWT
// (SD-JWT VC) or a device signature (mdoc) that the Relying Party verifies with that key. `RP_WS_SM_DeviceBinding_012_UF`
// (proximity, DeviceMac) is not written: the harness has no ISO/IEC 18013-5 proximity flow.
import {
  acc,
  type FaultId,
  type FormatWording,
  formats,
  PID,
  presentationStep,
  rej,
  rejOrAcc,
  relevancy,
  step,
} from '@rp-conformance/core';
import { bindingTestCase, oidf, rejected } from './binding';

const sdJwtVc = formats.sdJwtVc;
const mdoc = formats.mdoc;
const deviceBinding = (testCase: Parameters<typeof bindingTestCase>[1]) => bindingTestCase('DeviceBinding', testCase);

const KB_JWT = ['[RFC9901] section 7.3'];
const DEVICE_AUTH = ['[ISO/IEC 18013-5] section 9.1.3', '[OpenID4VP] section B.2.6'];

const byFormat = <T,>(format: FormatWording, sdJwtVcValue: T, mdocValue: T) => (format === sdJwtVc ? sdJwtVcValue : mdocValue);

/** DeviceBinding_007: a PID that is bound to no key, presented with the Conformance Wallet's own proof. */
const unbound = (format: FormatWording) =>
  deviceBinding({
    number: 7,
    variant: format.letter,
    format,
    relevancy: relevancy.specificRequired,
    objective: `Verify that the Relying Party rejects a PID in ${format.name} format that is not bound to a key of the Wallet Unit.`,
    references: ['[OpenID4VP] section 6.1, 8.6', '[ARF] section 6.6.3.8', ...byFormat(format, KB_JWT, DEVICE_AUTH)],
    steps: [
      step({
        ...presentationStep.credentialFault(byFormat<FaultId>(format, 'credential.no-cnf', 'mdoc.no-device-key')),
        expect: rej(),
      }),
    ],
    comments: [
      `The Conformance Wallet still ${byFormat(format, 'appends a KB-JWT signed', 'adds a device signature made')} with its own key, so the missing binding in the credential is the only difference from a valid presentation.`,
    ],
  });

/** DeviceBinding_013: device authentication with ES256K, by a key on secp256k1 the credential is bound to. */
const es256k = (format: FormatWording) =>
  deviceBinding({
    number: 13,
    variant: format.letter,
    format,
    relevancy: relevancy.specificRequired,
    objective: `Verify that the Relying Party rejects device authentication in ${format.name} format with an algorithm outside the agreed cryptographic mechanisms.`,
    references: ['[ECCG ACM]', '[HAIP] section 7', '[ARF] Annex 2, OIA_03', ...byFormat(format, KB_JWT, DEVICE_AUTH)],
    steps: [rejected(byFormat<FaultId>(format, 'presentation.kb-es256k', 'presentation.device-signature-es256k'))],
    comments: [
      'The credential is bound to the key that makes the device authentication, so the algorithm and its curve are the only difference from a valid presentation.',
    ],
  });

export const definitions = [
  deviceBinding({
    number: 1,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT signature is invalid.',
    references: [...KB_JWT, '[ARF] Annex 2, OIA_17'],
    steps: [rejected('presentation.kb-signature-bitflip')],
    comments: [oidf('invalid-kb-jwt-signature')],
  }),
  deviceBinding({
    number: 2,
    format: sdJwtVc,
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT is validly signed with a key other than the one the credential is bound to.',
    references: ['[SD-JWT VC] section 2.4', ...KB_JWT],
    steps: [rejected('presentation.kb-other-key')],
  }),
  deviceBinding({
    number: 3,
    format: sdJwtVc,
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format without a KB-JWT when the credential is bound to a key and the request requires holder binding.',
    references: [...KB_JWT, '[OpenID4VP] section 8.6', '[HAIP] section 6.1'],
    steps: [rejected('presentation.no-kb-jwt')],
  }),
  deviceBinding({
    number: 4,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT is not of type `kb+jwt`.',
    references: ['[RFC9901] section 4.3, 7.3'],
    steps: [rejected('presentation.kb-typ-missing'), rejected('presentation.kb-typ-jwt')],
  }),
  deviceBinding({
    number: 5,
    format: sdJwtVc,
    objective: 'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT `sd_hash` does not match the presented SD-JWT.',
    references: ['[RFC9901] section 4.3, 7.3'],
    steps: [rejected('presentation.kb-sd-hash-other')],
    comments: [oidf('invalid-sd-hash')],
  }),
  deviceBinding({
    number: 6,
    format: sdJwtVc,
    objective:
      'Verify that the Relying Party rejects a presentation in SD-JWT VC format whose KB-JWT is unsecured or protected with a symmetric algorithm keyed with the public key of the holder.',
    references: [...KB_JWT, '[RFC8725] section 3.1, 3.2'],
    steps: [rejected('presentation.kb-alg-none'), rejected('presentation.kb-hs256-public-key')],
  }),
  unbound(sdJwtVc),
  unbound(mdoc),
  deviceBinding({
    number: 8,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a presentation in mdoc format whose device signature is invalid.',
    references: DEVICE_AUTH,
    steps: [rejected('presentation.device-signature-bitflip'), rejected('presentation.device-signature-doctype-other')],
  }),
  deviceBinding({
    number: 9,
    format: mdoc,
    objective:
      'Verify that the Relying Party rejects a presentation in mdoc format whose device signature is made with a key other than the device key in its MSO.',
    references: DEVICE_AUTH,
    steps: [rejected('presentation.device-signature-other-key')],
  }),
  deviceBinding({
    number: 10,
    format: mdoc,
    objective: 'Verify that the Relying Party rejects a presentation in mdoc format without device authentication.',
    references: DEVICE_AUTH,
    steps: [rejected('presentation.no-device-auth'), rejected('presentation.device-signature-missing')],
  }),
  deviceBinding({
    number: 11,
    format: mdoc,
    relevancy: relevancy.specificRequired,
    objective: 'Verify that the Relying Party does not take a device-signed data element of a presentation in mdoc format as a PID attribute.',
    references: ['[ISO/IEC 18013-5] section 9.1.3', '[ARF] section 6.6.3.6'],
    steps: [
      step({
        ...presentationStep.presentationFault('presentation.device-signed-element'),
        expect: rejOrAcc({ credential: PID, extra: 'In neither case does it release the device-signed value `Musterfrau`.' }),
      }),
    ],
    comments: [
      'Data elements in `DeviceNameSpaces` are signed by the Wallet Unit, not by the PID Provider. The MSO of `default_credential_pid` carries no `keyAuthorizations`, so it authorises none of them.',
    ],
  }),
  es256k(sdJwtVc),
  es256k(mdoc),
  deviceBinding({
    number: 14,
    format: sdJwtVc,
    unhappyFlow: false,
    objective: 'Verify that the Relying Party accepts a credential in SD-JWT VC format whose `cnf.jwk` carries only the required JWK members.',
    references: ['[RFC7800] section 3.2', '[SD-JWT VC] section 2.2.2.2', '[HAIP] section 6.1'],
    steps: [step({ ...presentationStep.credentialFault('credential.minimal-cnf-jwk'), expect: acc({ credential: PID }) })],
    comments: [oidf('minimal-cnf-jwk')],
  }),
];
