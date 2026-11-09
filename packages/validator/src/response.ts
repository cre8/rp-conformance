import { base64url } from '@rp-conformance/forge';
import { compactDecrypt } from 'jose';
import { CheckFailure, CheckRecorder, type ValidationMode, type ValidationResult } from './checks';

export interface TransactionKey {
  kid?: string;
  privateKey: CryptoKey;
}

export interface ResponseValidationOptions {
  /** The encryption keys of this transaction; a JWE `kid` selects among them, and no other key is tried. */
  keys: TransactionKey[];
  /** `encrypted_response_enc_values_supported` of the request. */
  encValues: string[];
  /** `state` of the request, if any. */
  state?: string;
  mode?: ValidationMode;
}

export interface ResponseValidation extends ValidationResult {
  /** The decrypted payload: `vp_token`, `state` and any other member. */
  payload?: Record<string, unknown>;
}

const fail = (message: string): never => {
  throw new CheckFailure(message);
};

/**
 * Validates an Authorization Response in response mode `direct_post.jwt` (OpenID4VP section 8.3.1, HAIP section 5): an
 * encrypted `response` parameter, a JWE with `ECDH-ES` on P-256 and a content encryption the request listed, a valid
 * ephemeral key, decryption with this transaction's key, and a payload with `vp_token` and the request's `state`.
 */
export async function validateAuthorizationResponse(form: Record<string, string>, options: ResponseValidationOptions): Promise<ResponseValidation> {
  const recorder = new CheckRecorder(options.mode ?? 'first-failure');
  let header: Record<string, unknown> = {};
  let payload: Record<string, unknown> | undefined;
  // In `all` mode an unencrypted response is still read, so its credential can be shown to be valid.
  let plain: Record<string, unknown> | undefined;
  const result = await recorder.collect(async () => {
    await recorder.run('response-encrypted', [], () => {
      if (typeof form.response === 'string') return;
      if (form.vp_token !== undefined) {
        try {
          plain = { vp_token: JSON.parse(form.vp_token), ...(form.state !== undefined ? { state: form.state } : {}) };
        } catch {
          plain = undefined;
        }
      }
      fail('the response is not encrypted: no response parameter');
    });
    await recorder.run('response-format', ['response-encrypted'], () => {
      const parts = form.response.split('.');
      if (parts.length !== 5) fail(`not a compact JWE (${parts.length} parts)`);
      try {
        header = base64url.decodeJson(parts[0] ?? '');
      } catch {
        fail('the JWE protected header cannot be decoded');
      }
    });
    await recorder.run('response-alg', ['response-format'], () => {
      if (header.alg !== 'ECDH-ES') fail(`alg ${String(header.alg)}, expected ECDH-ES`);
    });
    await recorder.run('response-enc', ['response-format'], () => {
      if (!options.encValues.includes(String(header.enc))) fail(`enc ${String(header.enc)} is not one the request listed (${options.encValues.join(', ')})`);
    });
    await recorder.run('response-epk', ['response-format'], async () => {
      const epk = header.epk as JsonWebKey | undefined;
      if (!epk || epk.kty !== 'EC' || epk.crv !== 'P-256') fail(`epk is not an EC P-256 key (crv ${String(epk?.crv)})`);
      try {
        await globalThis.crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: epk?.x, y: epk?.y }, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
      } catch {
        fail('epk is not a point on P-256');
      }
    });
    await recorder.run('response-decryption', ['response-alg', 'response-enc', 'response-epk'], async () => {
      const kid = header.kid;
      const key = kid !== undefined ? options.keys.find((k) => k.kid === kid) : options.keys.length === 1 ? options.keys[0] : undefined;
      if (!key) fail(`no encryption key of this transaction has kid ${String(kid)}`);
      try {
        const { plaintext } = await compactDecrypt(form.response, (key as TransactionKey).privateKey, {
          keyManagementAlgorithms: ['ECDH-ES'],
          contentEncryptionAlgorithms: options.encValues,
        });
        payload = JSON.parse(new TextDecoder().decode(plaintext));
      } catch (error) {
        fail(`decryption failed: ${(error as Error).message}`);
      }
    });
    await recorder.run('response-payload', plain ? [] : ['response-decryption'], () => {
      const content = payload ?? plain;
      if (!content || typeof content !== 'object' || Array.isArray(content)) fail('the payload is not a JSON object');
      const vpToken = (content as Record<string, unknown>).vp_token;
      if (!vpToken || typeof vpToken !== 'object' || Array.isArray(vpToken)) fail('vp_token is missing or not a DCQL presentation object');
      if (options.state !== undefined && (content as Record<string, unknown>).state !== options.state) fail('state does not match the request');
      payload = content as Record<string, unknown>;
    });
  });
  return { ...result, payload };
}
