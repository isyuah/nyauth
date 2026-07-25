/**
 * nyauth TypeScript SDK
 *
 * A client library for authenticating with a nyauth OAuth 2.0 / OpenID Connect server.
 *
 * @example
 * ```typescript
 * import { NyAuthClient } from '@nyasharp/nyauth';
 *
 * const client = new NyAuthClient({
 *   issuer: 'https://auth.example.com',
 *   clientId: 'my-app',
 *   clientSecret: 'secret',
 *   redirectUri: 'https://my-app.com/callback',
 * });
 *
 * // Authorization Code Flow with PKCE
 * const { url, state, codeVerifier } = client.getAuthorizationURLPKCE(['openid', 'profile']);
 * // Redirect user to url...
 * // On callback:
 * const token = await client.exchangeCodePKCE(code, codeVerifier);
 * const user = await client.getUserInfo(token.access_token);
 * ```
 */

import type {
  NyAuthConfig,
  TokenResponse,
  UserInfo,
  DiscoveryDocument,
  AuthorizationResult,
  PKCEResult,
} from './types.js';

export type {
  NyAuthConfig,
  TokenResponse,
  UserInfo,
  DiscoveryDocument,
  AuthorizationResult,
  PKCEResult,
};

export class NyAuthClient {
  private config: NyAuthConfig;

  constructor(config: NyAuthConfig) {
    this.config = config;
  }

  /**
   * Fetches the OIDC discovery document from the issuer.
   */
  async discover(): Promise<DiscoveryDocument> {
    const url = `${this.config.issuer}/.well-known/openid-configuration`;
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`Discovery failed: ${resp.status}`);
    return resp.json();
  }

  /**
   * Generates an authorization URL with a random state.
   */
  getAuthorizationURL(scopes: string[], state?: string): AuthorizationResult {
    if (!state) state = generateRandomState();

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: scopes.join(' '),
      state,
    });

    return {
      url: `${this.config.issuer}/authorize?${params}`,
      state,
    };
  }

  /**
   * Generates an authorization URL with PKCE (recommended for public clients).
   */
  getAuthorizationURLPKCE(scopes: string[], state?: string): PKCEResult {
    if (!state) state = generateRandomState();

    const codeVerifier = generateCodeVerifier();
    const codeChallenge = computeS256Challenge(codeVerifier);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: scopes.join(' '),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return {
      url: `${this.config.issuer}/authorize?${params}`,
      state,
      codeVerifier,
      codeChallenge,
    };
  }

  /**
   * Exchanges an authorization code for tokens.
   */
  async exchangeCode(code: string): Promise<TokenResponse> {
    return this.exchangeCodePKCE(code, '');
  }

  /**
   * Exchanges an authorization code for tokens with PKCE.
   */
  async exchangeCodePKCE(code: string, codeVerifier: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
    });

    if (codeVerifier) {
      params.set('code_verifier', codeVerifier);
    }

    return this.tokenRequest(params);
  }

  /**
   * Performs the client credentials grant.
   */
  async clientCredentialsGrant(scopes?: string[]): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
    });

    if (scopes && scopes.length > 0) {
      params.set('scope', scopes.join(' '));
    }

    return this.tokenRequest(params);
  }

  /**
   * Refreshes an access token using a refresh token.
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    });

    return this.tokenRequest(params);
  }

  /**
   * Retrieves user information using an access token.
   */
  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const resp = await fetch(`${this.config.issuer}/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!resp.ok) throw new Error(`UserInfo failed: ${resp.status}`);
    return resp.json();
  }

  /**
   * Introspects a token (RFC 7662).
   */
  async introspectToken(token: string): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({ token });
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (this.config.clientSecret) {
      const auth = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
      headers['Authorization'] = `Basic ${auth}`;
    } else {
      params.set('client_id', this.config.clientId);
    }

    const resp = await fetch(`${this.config.issuer}/introspect`, {
      method: 'POST',
      headers,
      body: params,
    });

    if (!resp.ok) throw new Error(`Introspect failed: ${resp.status}`);
    return resp.json();
  }

  /**
   * Revokes a token (RFC 7009).
   */
  async revokeToken(token: string): Promise<void> {
    const params = new URLSearchParams({ token });
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    if (this.config.clientSecret) {
      const auth = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
      headers['Authorization'] = `Basic ${auth}`;
    }

    const resp = await fetch(`${this.config.issuer}/revoke`, {
      method: 'POST',
      headers,
      body: params,
    });

    if (!resp.ok) throw new Error(`Revoke failed: ${resp.status}`);
  }

  private async tokenRequest(params: URLSearchParams): Promise<TokenResponse> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    };

    if (this.config.clientSecret) {
      const auth = btoa(`${this.config.clientId}:${this.config.clientSecret}`);
      headers['Authorization'] = `Basic ${auth}`;
    } else {
      params.set('client_id', this.config.clientId);
    }

    const resp = await fetch(`${this.config.issuer}/token`, {
      method: 'POST',
      headers,
      body: params,
    });

    const body = await resp.json();
    if (!resp.ok) {
      const err = body as { error?: string; error_description?: string };
      throw new Error(err.error_description || err.error || `Token request failed: ${resp.status}`);
    }

    return body as TokenResponse;
  }
}

// --- Utilities ---

function generateRandomState(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function generateCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function computeS256Challenge(verifier: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  // Use SubtleCrypto for SHA-256 (async in browser, but we use sync fallback)
  // For synchronous use, we do a simple hash
  return base64UrlEncode(sha256Sync(data));
}

function sha256Sync(data: Uint8Array): Uint8Array {
  // Simple synchronous SHA-256 for environments without SubtleCrypto
  // This is a basic implementation - for production, use a library
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  // Pad the message
  const bitLen = data.length * 8;
  const padLen = (64 - ((data.length + 9) % 64)) % 64;
  const padded = new Uint8Array(data.length + 1 + padLen + 8);
  padded.set(data);
  padded[data.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(padded.length - 4, bitLen);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  for (let offset = 0; offset < padded.length; offset += 64) {
    const w = new Uint32Array(64);
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) | 0;

      h = g; g = f; f = e; e = (d + temp1) | 0;
      d = c; c = b; b = a; a = (temp1 + temp2) | 0;
    }

    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }

  const result = new Uint8Array(32);
  const resultView = new DataView(result.buffer);
  resultView.setUint32(0, h0); resultView.setUint32(4, h1);
  resultView.setUint32(8, h2); resultView.setUint32(12, h3);
  resultView.setUint32(16, h4); resultView.setUint32(20, h5);
  resultView.setUint32(24, h6); resultView.setUint32(28, h7);

  return result;
}

function rightRotate(value: number, amount: number): number {
  return (value >>> amount) | (value << (32 - amount));
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
