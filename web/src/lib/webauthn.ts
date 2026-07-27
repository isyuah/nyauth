const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export const WEBAUTHN_ERROR_CODES = {
  aborted: 'aborted',
  notAllowed: 'not_allowed',
  invalidState: 'invalid_state',
  notSupported: 'not_supported',
  security: 'security_error',
  unknown: 'unknown',
} as const;

export type WebAuthnErrorCode = typeof WEBAUTHN_ERROR_CODES[keyof typeof WEBAUTHN_ERROR_CODES];

export interface WebAuthnPublicKeyCredentialStatics {
  parseCreationOptionsFromJSON?: (
    options: PublicKeyCredentialCreationOptionsJSON,
  ) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (
    options: PublicKeyCredentialRequestOptionsJSON,
  ) => PublicKeyCredentialRequestOptions;
  isConditionalMediationAvailable?: () => Promise<boolean>;
}

export interface WebAuthnCredentialsContainer {
  create(options: CredentialCreationOptions): Promise<Credential | null>;
  get(options: CredentialRequestOptions): Promise<Credential | null>;
}

export interface WebAuthnRuntime {
  publicKeyCredential?: WebAuthnPublicKeyCredentialStatics;
  credentials?: WebAuthnCredentialsContainer;
  isSecureContext?: boolean;
}

export interface CreateCredentialOptions {
  signal?: AbortSignal;
  runtime?: WebAuthnRuntime;
}

export interface GetCredentialOptions extends CreateCredentialOptions {
  mediation?: CredentialMediationRequirement;
}

export interface WebAuthnCredentialJSONBase {
  id: string;
  rawId: string;
  type: string;
  authenticatorAttachment: string | null;
  clientExtensionResults: unknown;
}

export interface WebAuthnRegistrationCredentialJSON extends WebAuthnCredentialJSONBase {
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports: string[];
    authenticatorData?: string;
    publicKey?: string | null;
    publicKeyAlgorithm?: number;
  };
}

export interface WebAuthnAuthenticationCredentialJSON extends WebAuthnCredentialJSONBase {
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
}

type PublicKeyCredentialWithOptionalJSON = Omit<PublicKeyCredential, 'toJSON'> & {
  toJSON?: () => unknown;
};

interface AttestationResponseLike extends AuthenticatorResponse {
  attestationObject: ArrayBuffer;
  getAuthenticatorData?: () => ArrayBuffer;
  getPublicKey?: () => ArrayBuffer | null;
  getPublicKeyAlgorithm?: () => number;
  getTransports?: () => string[];
}

interface AssertionResponseLike extends AuthenticatorResponse {
  authenticatorData: ArrayBuffer;
  signature: ArrayBuffer;
  userHandle: ArrayBuffer | null;
}

function browserRuntime(): WebAuthnRuntime {
  const scope = globalThis as unknown as {
    PublicKeyCredential?: WebAuthnPublicKeyCredentialStatics;
    navigator?: { credentials?: WebAuthnCredentialsContainer };
    isSecureContext?: boolean;
  };

  return {
    publicKeyCredential: scope.PublicKeyCredential,
    credentials: scope.navigator?.credentials,
    isSecureContext: scope.isSecureContext,
  };
}

function resolveRuntime(runtime?: WebAuthnRuntime): WebAuthnRuntime {
  return runtime ?? browserRuntime();
}

function namedError(name: string, message: string): Error {
  const error = new Error(message);
  error.name = name;
  return error;
}

function bytesFromBufferSource(value: BufferSource): Uint8Array {
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value);
}

function isArrayBuffer(value: unknown): value is ArrayBuffer {
  return value instanceof ArrayBuffer || Object.prototype.toString.call(value) === '[object ArrayBuffer]';
}

function isBufferSource(value: unknown): value is BufferSource {
  return isArrayBuffer(value) || ArrayBuffer.isView(value);
}

export function encodeBase64Url(value: BufferSource): string {
  const bytes = bytesFromBufferSource(value);
  let encoded = '';

  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index];
    const second = index + 1 < bytes.length ? bytes[index + 1] : 0;
    const third = index + 2 < bytes.length ? bytes[index + 2] : 0;
    const chunk = (first << 16) | (second << 8) | third;

    encoded += BASE64_ALPHABET[(chunk >>> 18) & 0x3f];
    encoded += BASE64_ALPHABET[(chunk >>> 12) & 0x3f];
    if (index + 1 < bytes.length) encoded += BASE64_ALPHABET[(chunk >>> 6) & 0x3f];
    if (index + 2 < bytes.length) encoded += BASE64_ALPHABET[chunk & 0x3f];
  }

  return encoded.replaceAll('+', '-').replaceAll('/', '_');
}

export function decodeBase64Url(value: string): ArrayBuffer {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || /=/.test(normalized.slice(0, -2))) {
    throw new TypeError('Invalid base64url value');
  }

  const unpadded = normalized.replace(/=+$/, '');
  if (unpadded.length % 4 === 1) throw new TypeError('Invalid base64url value');

  const output: number[] = [];
  let accumulator = 0;
  let bits = 0;

  for (const character of unpadded) {
    const digit = BASE64_ALPHABET.indexOf(character);
    if (digit < 0) throw new TypeError('Invalid base64url value');
    accumulator = ((accumulator << 6) | digit) & 0x00ffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 0xff);
    }
  }

  if (bits > 0 && (accumulator & ((1 << bits) - 1)) !== 0) {
    throw new TypeError('Invalid base64url value');
  }

  return Uint8Array.from(output).buffer;
}

function parseDescriptor(
  descriptor: PublicKeyCredentialDescriptorJSON,
): PublicKeyCredentialDescriptor {
  return {
    ...descriptor,
    id: decodeBase64Url(descriptor.id),
    transports: descriptor.transports as AuthenticatorTransport[] | undefined,
    type: descriptor.type as PublicKeyCredentialType,
  };
}

function parsePRFValues(
  values: AuthenticationExtensionsPRFValuesJSON | undefined,
): AuthenticationExtensionsPRFValues | undefined {
  if (!values) return undefined;
  return {
    first: decodeBase64Url(values.first),
    second: values.second === undefined ? undefined : decodeBase64Url(values.second),
  };
}

function parseExtensions(
  extensions: AuthenticationExtensionsClientInputsJSON | undefined,
): AuthenticationExtensionsClientInputs | undefined {
  if (!extensions) return undefined;

  const parsed = { ...extensions } as unknown as AuthenticationExtensionsClientInputs;
  if (extensions.largeBlob) {
    parsed.largeBlob = {
      ...extensions.largeBlob,
      write: extensions.largeBlob.write === undefined
        ? undefined
        : decodeBase64Url(extensions.largeBlob.write),
    };
  }
  if (extensions.prf) {
    const evalByCredential = extensions.prf.evalByCredential
      ? Object.fromEntries(Object.entries(extensions.prf.evalByCredential).map(([id, values]) => [
        id,
        parsePRFValues(values)!,
      ]))
      : undefined;
    parsed.prf = {
      eval: parsePRFValues(extensions.prf.eval),
      evalByCredential,
    };
  }
  return parsed;
}

export function creationOptionsFromJSON(
  options: PublicKeyCredentialCreationOptionsJSON,
  runtime?: WebAuthnRuntime,
): PublicKeyCredentialCreationOptions {
  const statics = resolveRuntime(runtime).publicKeyCredential;
  if (typeof statics?.parseCreationOptionsFromJSON === 'function') {
    return statics.parseCreationOptionsFromJSON.call(statics, options);
  }

  const { challenge, user, excludeCredentials, extensions, ...rest } = options;
  return {
    ...rest,
    challenge: decodeBase64Url(challenge),
    user: { ...user, id: decodeBase64Url(user.id) },
    excludeCredentials: excludeCredentials?.map(parseDescriptor),
    extensions: parseExtensions(extensions),
  } as unknown as PublicKeyCredentialCreationOptions;
}

export function requestOptionsFromJSON(
  options: PublicKeyCredentialRequestOptionsJSON,
  runtime?: WebAuthnRuntime,
): PublicKeyCredentialRequestOptions {
  const statics = resolveRuntime(runtime).publicKeyCredential;
  if (typeof statics?.parseRequestOptionsFromJSON === 'function') {
    return statics.parseRequestOptionsFromJSON.call(statics, options);
  }

  const { challenge, allowCredentials, extensions, ...rest } = options;
  return {
    ...rest,
    challenge: decodeBase64Url(challenge),
    allowCredentials: allowCredentials?.map(parseDescriptor),
    extensions: parseExtensions(extensions),
  } as unknown as PublicKeyCredentialRequestOptions;
}

function serializeBinaryValues(value: unknown): unknown {
  if (isBufferSource(value)) return encodeBase64Url(value);
  if (Array.isArray(value)) return value.map(serializeBinaryValues);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [
      key,
      serializeBinaryValues(nested),
    ]));
  }
  return value;
}

function nativeCredentialJSON<T>(credential: PublicKeyCredential): T | null {
  const toJSON = (credential as PublicKeyCredentialWithOptionalJSON).toJSON;
  if (typeof toJSON !== 'function') return null;
  const serialized = toJSON.call(credential);
  if (!serialized || typeof serialized !== 'object') {
    throw new TypeError('PublicKeyCredential.toJSON() returned an invalid value');
  }
  return serialized as T;
}

function credentialBaseJSON(credential: PublicKeyCredential): WebAuthnCredentialJSONBase {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: serializeBinaryValues(credential.getClientExtensionResults()),
  };
}

export function registrationCredentialToJSON(
  credential: PublicKeyCredential,
): WebAuthnRegistrationCredentialJSON {
  const native = nativeCredentialJSON<WebAuthnRegistrationCredentialJSON>(credential);
  if (native) return native;

  const response = credential.response as AttestationResponseLike;
  const serialized: WebAuthnRegistrationCredentialJSON = {
    ...credentialBaseJSON(credential),
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      attestationObject: encodeBase64Url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  };

  if (typeof response.getAuthenticatorData === 'function') {
    serialized.response.authenticatorData = encodeBase64Url(response.getAuthenticatorData());
  }
  if (typeof response.getPublicKey === 'function') {
    const publicKey = response.getPublicKey();
    serialized.response.publicKey = publicKey === null ? null : encodeBase64Url(publicKey);
  }
  if (typeof response.getPublicKeyAlgorithm === 'function') {
    serialized.response.publicKeyAlgorithm = response.getPublicKeyAlgorithm();
  }

  return serialized;
}

export function authenticationCredentialToJSON(
  credential: PublicKeyCredential,
): WebAuthnAuthenticationCredentialJSON {
  const native = nativeCredentialJSON<WebAuthnAuthenticationCredentialJSON>(credential);
  if (native) return native;

  const response = credential.response as AssertionResponseLike;
  return {
    ...credentialBaseJSON(credential),
    response: {
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      authenticatorData: encodeBase64Url(response.authenticatorData),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle === null ? null : encodeBase64Url(response.userHandle),
    },
  };
}

function requireCredentials(runtime: WebAuthnRuntime): WebAuthnCredentialsContainer {
  if (runtime.isSecureContext === false) {
    throw namedError('SecurityError', 'WebAuthn requires a secure context');
  }
  if (!runtime.credentials) {
    throw namedError('NotSupportedError', 'WebAuthn is not supported by this browser');
  }
  return runtime.credentials;
}

function requirePublicKeyCredential(credential: Credential | null): PublicKeyCredential {
  if (!credential || credential.type !== 'public-key') {
    throw namedError('NotAllowedError', 'No public-key credential was returned');
  }
  return credential as PublicKeyCredential;
}

export async function createCredential(
  options: PublicKeyCredentialCreationOptionsJSON,
  configuration: CreateCredentialOptions = {},
): Promise<PublicKeyCredential> {
  const runtime = resolveRuntime(configuration.runtime);
  const credentials = requireCredentials(runtime);
  const credential = await credentials.create({
    publicKey: creationOptionsFromJSON(options, runtime),
    signal: configuration.signal,
  });
  return requirePublicKeyCredential(credential);
}

export async function getCredential(
  options: PublicKeyCredentialRequestOptionsJSON,
  configuration: GetCredentialOptions = {},
): Promise<PublicKeyCredential> {
  const runtime = resolveRuntime(configuration.runtime);
  const credentials = requireCredentials(runtime);
  const request: CredentialRequestOptions = {
    publicKey: requestOptionsFromJSON(options, runtime),
    signal: configuration.signal,
  };
  if (configuration.mediation !== undefined) request.mediation = configuration.mediation;
  const credential = await credentials.get(request);
  return requirePublicKeyCredential(credential);
}

export async function isConditionalMediationAvailable(
  runtime?: WebAuthnRuntime,
): Promise<boolean> {
  const resolved = resolveRuntime(runtime);
  if (resolved.isSecureContext === false || !resolved.credentials) return false;
  const check = resolved.publicKeyCredential?.isConditionalMediationAvailable;
  if (typeof check !== 'function') return false;
  try {
    return await check.call(resolved.publicKeyCredential) === true;
  } catch {
    return false;
  }
}

export function classifyWebAuthnError(error: unknown): WebAuthnErrorCode {
  const name = error && typeof error === 'object' && 'name' in error
    ? String((error as { name?: unknown }).name)
    : '';

  switch (name) {
    case 'AbortError':
      return WEBAUTHN_ERROR_CODES.aborted;
    case 'NotAllowedError':
      return WEBAUTHN_ERROR_CODES.notAllowed;
    case 'InvalidStateError':
      return WEBAUTHN_ERROR_CODES.invalidState;
    case 'NotSupportedError':
      return WEBAUTHN_ERROR_CODES.notSupported;
    case 'SecurityError':
      return WEBAUTHN_ERROR_CODES.security;
    default:
      return WEBAUTHN_ERROR_CODES.unknown;
  }
}
