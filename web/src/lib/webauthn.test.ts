import { describe, expect, it, vi } from 'vitest';
import {
  WEBAUTHN_ERROR_CODES,
  authenticationCredentialToJSON,
  classifyWebAuthnError,
  createCredential,
  creationOptionsFromJSON,
  decodeBase64Url,
  encodeBase64Url,
  getCredential,
  isConditionalMediationAvailable,
  registrationCredentialToJSON,
  requestOptionsFromJSON,
  type WebAuthnCredentialsContainer,
  type WebAuthnRuntime,
} from './webauthn';

function buffer(...values: number[]): ArrayBuffer {
  return Uint8Array.from(values).buffer;
}

function bytes(value: BufferSource): number[] {
  const view = ArrayBuffer.isView(value)
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value);
  return Array.from(view);
}

function credentialBase(overrides: Record<string, unknown> = {}): PublicKeyCredential {
  return {
    id: 'credential-id',
    rawId: buffer(0xfb, 0xff, 0xef),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    getClientExtensionResults: () => ({}),
    ...overrides,
  } as unknown as PublicKeyCredential;
}

describe('base64url conversion', () => {
  it('round-trips binary data without standard alphabet characters or padding', () => {
    const original = buffer(0xfb, 0xff, 0xef, 0x00, 0x01);
    const encoded = encodeBase64Url(original);

    expect(encoded).toBe('-__vAAE');
    expect(encoded).not.toMatch(/[+/=]/);
    expect(bytes(decodeBase64Url(encoded))).toEqual(bytes(original));
  });

  it('accepts an optional padded representation while keeping output unpadded', () => {
    expect(bytes(decodeBase64Url('_w=='))).toEqual([255]);
    expect(encodeBase64Url(buffer(255))).toBe('_w');
  });

  it('rejects malformed base64url values and non-zero trailing bits', () => {
    expect(() => decodeBase64Url('a')).toThrow(TypeError);
    expect(() => decodeBase64Url('_x')).toThrow(TypeError);
    expect(() => decodeBase64Url('abc$')).toThrow(TypeError);
  });
});

describe('WebAuthn option parsing', () => {
  const creationJSON: PublicKeyCredentialCreationOptionsJSON = {
    challenge: encodeBase64Url(buffer(1, 2, 3, 4)),
    rp: { id: 'example.test', name: 'Example' },
    user: {
      id: encodeBase64Url(buffer(5, 6, 7, 8)),
      name: 'alice',
      displayName: 'Alice',
    },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [{
      type: 'public-key',
      id: encodeBase64Url(buffer(9, 10, 11)),
      transports: ['internal', 'hybrid'],
    }],
    extensions: {
      largeBlob: { write: encodeBase64Url(buffer(12, 13)) },
      prf: {
        eval: {
          first: encodeBase64Url(buffer(14, 15)),
          second: encodeBase64Url(buffer(16, 17)),
        },
        evalByCredential: {
          credential: { first: encodeBase64Url(buffer(18, 19)) },
        },
      },
    },
  };

  const requestJSON: PublicKeyCredentialRequestOptionsJSON = {
    challenge: encodeBase64Url(buffer(21, 22, 23)),
    rpId: 'example.test',
    allowCredentials: [{
      type: 'public-key',
      id: encodeBase64Url(buffer(24, 25, 26)),
      transports: ['usb'],
    }],
    userVerification: 'required',
    extensions: {
      prf: { eval: { first: encodeBase64Url(buffer(27, 28)) } },
    },
  };

  it('manually converts all binary creation-option fields when the native helper is absent', () => {
    const parsed = creationOptionsFromJSON(creationJSON, {});

    expect(bytes(parsed.challenge)).toEqual([1, 2, 3, 4]);
    expect(bytes(parsed.user.id)).toEqual([5, 6, 7, 8]);
    expect(bytes(parsed.excludeCredentials![0].id)).toEqual([9, 10, 11]);
    expect(parsed.excludeCredentials![0].transports).toEqual(['internal', 'hybrid']);
    expect(bytes(parsed.extensions!.largeBlob!.write!)).toEqual([12, 13]);
    expect(bytes(parsed.extensions!.prf!.eval!.first)).toEqual([14, 15]);
    expect(bytes(parsed.extensions!.prf!.eval!.second!)).toEqual([16, 17]);
    expect(bytes(parsed.extensions!.prf!.evalByCredential!.credential.first)).toEqual([18, 19]);
  });

  it('manually converts request challenge, allowCredentials, and extension binary data', () => {
    const parsed = requestOptionsFromJSON(requestJSON, {});

    expect(bytes(parsed.challenge)).toEqual([21, 22, 23]);
    expect(bytes(parsed.allowCredentials![0].id)).toEqual([24, 25, 26]);
    expect(parsed.allowCredentials![0].transports).toEqual(['usb']);
    expect(bytes(parsed.extensions!.prf!.eval!.first)).toEqual([27, 28]);
  });

  it('prefers both native parse helpers when they are available', () => {
    const nativeCreation = { challenge: buffer(31) } as PublicKeyCredentialCreationOptions;
    const nativeRequest = { challenge: buffer(32) } as PublicKeyCredentialRequestOptions;
    const parseCreationOptionsFromJSON = vi.fn(() => nativeCreation);
    const parseRequestOptionsFromJSON = vi.fn(() => nativeRequest);
    const runtime: WebAuthnRuntime = {
      publicKeyCredential: { parseCreationOptionsFromJSON, parseRequestOptionsFromJSON },
    };

    expect(creationOptionsFromJSON(creationJSON, runtime)).toBe(nativeCreation);
    expect(requestOptionsFromJSON(requestJSON, runtime)).toBe(nativeRequest);
    expect(parseCreationOptionsFromJSON).toHaveBeenCalledWith(creationJSON);
    expect(parseRequestOptionsFromJSON).toHaveBeenCalledWith(requestJSON);
  });
});

describe('credential serialization', () => {
  it('serializes a registration credential and nested binary extension output via fallback', () => {
    const credential = credentialBase({
      getClientExtensionResults: () => ({
        largeBlob: { blob: buffer(40, 41) },
        prf: { results: { first: buffer(42, 43) } },
      }),
      response: {
        clientDataJSON: buffer(44, 45),
        attestationObject: buffer(46, 47),
        getTransports: () => ['internal', 'hybrid'],
        getAuthenticatorData: () => buffer(48, 49),
        getPublicKey: () => buffer(50, 51),
        getPublicKeyAlgorithm: () => -7,
      },
    });

    const serialized = registrationCredentialToJSON(credential);

    expect(serialized).toEqual({
      id: 'credential-id',
      rawId: '-__v',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: {
        largeBlob: { blob: encodeBase64Url(buffer(40, 41)) },
        prf: { results: { first: encodeBase64Url(buffer(42, 43)) } },
      },
      response: {
        clientDataJSON: encodeBase64Url(buffer(44, 45)),
        attestationObject: encodeBase64Url(buffer(46, 47)),
        transports: ['internal', 'hybrid'],
        authenticatorData: encodeBase64Url(buffer(48, 49)),
        publicKey: encodeBase64Url(buffer(50, 51)),
        publicKeyAlgorithm: -7,
      },
    });
  });

  it('preserves a nullable userHandle in the authentication fallback', () => {
    const credential = credentialBase({
      authenticatorAttachment: null,
      response: {
        clientDataJSON: buffer(60),
        authenticatorData: buffer(61),
        signature: buffer(62),
        userHandle: null,
      },
    });

    expect(authenticationCredentialToJSON(credential)).toEqual({
      id: 'credential-id',
      rawId: '-__v',
      type: 'public-key',
      authenticatorAttachment: null,
      clientExtensionResults: {},
      response: {
        clientDataJSON: encodeBase64Url(buffer(60)),
        authenticatorData: encodeBase64Url(buffer(61)),
        signature: encodeBase64Url(buffer(62)),
        userHandle: null,
      },
    });
  });

  it('base64url-encodes a non-null authentication userHandle', () => {
    const credential = credentialBase({
      response: {
        clientDataJSON: buffer(63),
        authenticatorData: buffer(64),
        signature: buffer(65),
        userHandle: buffer(66, 67),
      },
    });

    expect(authenticationCredentialToJSON(credential).response.userHandle)
      .toBe(encodeBase64Url(buffer(66, 67)));
  });

  it('prefers native credential.toJSON without reading fallback response fields', () => {
    const nativeJSON = {
      id: 'native',
      rawId: 'bmF0aXZl',
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      clientExtensionResults: {},
      response: { clientDataJSON: 'Y2xpZW50', attestationObject: 'YXR0', transports: [] },
    };
    const toJSON = vi.fn(() => nativeJSON);
    const credential = credentialBase({ toJSON });

    expect(registrationCredentialToJSON(credential)).toBe(nativeJSON);
    expect(toJSON).toHaveBeenCalledOnce();
  });
});

describe('browser operation wrappers', () => {
  const creationJSON: PublicKeyCredentialCreationOptionsJSON = {
    challenge: encodeBase64Url(buffer(70)),
    rp: { name: 'Example' },
    user: { id: encodeBase64Url(buffer(71)), name: 'alice', displayName: 'Alice' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  };
  const requestJSON: PublicKeyCredentialRequestOptionsJSON = {
    challenge: encodeBase64Url(buffer(72)),
  };

  it('passes AbortSignal to create and passes both AbortSignal and mediation to get', async () => {
    const created = credentialBase({ response: {} });
    const asserted = credentialBase({ id: 'asserted', response: {} });
    const create = vi.fn(async () => created as unknown as Credential);
    const get = vi.fn(async () => asserted as unknown as Credential);
    const parsedCreation = { challenge: buffer(73) } as PublicKeyCredentialCreationOptions;
    const parsedRequest = { challenge: buffer(74) } as PublicKeyCredentialRequestOptions;
    const runtime: WebAuthnRuntime = {
      isSecureContext: true,
      credentials: { create, get },
      publicKeyCredential: {
        parseCreationOptionsFromJSON: () => parsedCreation,
        parseRequestOptionsFromJSON: () => parsedRequest,
      },
    };
    const controller = new AbortController();

    await expect(createCredential(creationJSON, { runtime, signal: controller.signal })).resolves.toBe(created);
    await expect(getCredential(requestJSON, {
      runtime,
      signal: controller.signal,
      mediation: 'conditional',
    })).resolves.toBe(asserted);

    expect(create).toHaveBeenCalledWith({ publicKey: parsedCreation, signal: controller.signal });
    expect(get).toHaveBeenCalledWith({
      publicKey: parsedRequest,
      signal: controller.signal,
      mediation: 'conditional',
    });
  });

  it('classifies wrapper failures when WebAuthn is unavailable or insecure', async () => {
    await expect(createCredential(creationJSON, { runtime: {} })).rejects.toMatchObject({
      name: 'NotSupportedError',
    });
    const credentials = {
      create: vi.fn(),
      get: vi.fn(),
    } as unknown as WebAuthnCredentialsContainer;
    await expect(getCredential(requestJSON, {
      runtime: { isSecureContext: false, credentials },
    })).rejects.toMatchObject({ name: 'SecurityError' });
  });
});

describe('conditional mediation capability', () => {
  function runtimeFor(check: () => Promise<boolean>): WebAuthnRuntime {
    return {
      isSecureContext: true,
      publicKeyCredential: { isConditionalMediationAvailable: check },
      credentials: {
        create: vi.fn(),
        get: vi.fn(),
      } as unknown as WebAuthnCredentialsContainer,
    };
  }

  it('returns true when the browser reports conditional mediation support', async () => {
    await expect(isConditionalMediationAvailable(runtimeFor(async () => true))).resolves.toBe(true);
  });

  it('returns false for an unsupported or insecure runtime', async () => {
    await expect(isConditionalMediationAvailable(runtimeFor(async () => false))).resolves.toBe(false);
    await expect(isConditionalMediationAvailable({ isSecureContext: false })).resolves.toBe(false);
    await expect(isConditionalMediationAvailable({ isSecureContext: true })).resolves.toBe(false);
  });

  it('returns false when the capability method throws', async () => {
    await expect(isConditionalMediationAvailable(runtimeFor(async () => {
      throw new Error('browser failure');
    }))).resolves.toBe(false);
  });
});

describe('WebAuthn error classification', () => {
  it.each([
    ['AbortError', WEBAUTHN_ERROR_CODES.aborted],
    ['NotAllowedError', WEBAUTHN_ERROR_CODES.notAllowed],
    ['InvalidStateError', WEBAUTHN_ERROR_CODES.invalidState],
    ['NotSupportedError', WEBAUTHN_ERROR_CODES.notSupported],
    ['SecurityError', WEBAUTHN_ERROR_CODES.security],
    ['UnknownError', WEBAUTHN_ERROR_CODES.unknown],
  ])('maps %s to %s', (name, expected) => {
    expect(classifyWebAuthnError({ name })).toBe(expected);
  });

  it('maps non-error values to unknown', () => {
    expect(classifyWebAuthnError(null)).toBe(WEBAUTHN_ERROR_CODES.unknown);
    expect(classifyWebAuthnError('AbortError')).toBe(WEBAUTHN_ERROR_CODES.unknown);
  });
});
