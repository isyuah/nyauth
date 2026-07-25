/**
 * nyauth TypeScript SDK for Authorization Code + S256 PKCE.
 *
 * @example
 * ```typescript
 * const client = new NyAuthClient({
 *   issuer: 'https://auth.example.com',
 *   clientId: 'my-public-app',
 *   redirectUri: 'https://app.example.com/callback',
 * });
 * const { url, state, codeVerifier } = await client.getAuthorizationURL(['openid', 'profile']);
 * sessionStorage.setItem('oauth_state', state);
 * sessionStorage.setItem('pkce_verifier', codeVerifier);
 * window.location.assign(url);
 * ```
 */

import type {
  NyAuthConfig,
  TokenResponse,
  UserInfo,
  DiscoveryDocument,
  PKCEResult,
} from './types.js';

export type { NyAuthConfig, TokenResponse, UserInfo, DiscoveryDocument, PKCEResult };

export class NyAuthClient {
  private readonly config: NyAuthConfig;
  private readonly issuer: string;

  constructor(config: NyAuthConfig) {
    this.config = config;
    this.issuer = config.issuer.replace(/\/$/, '');
  }

  async discover(): Promise<DiscoveryDocument> {
    const resp = await fetch(`${this.issuer}/.well-known/openid-configuration`);
    if (!resp.ok) throw new Error(`Discovery failed: ${resp.status}`);
    return resp.json() as Promise<DiscoveryDocument>;
  }

  /** Generates an authorization URL using mandatory S256 PKCE. */
  async getAuthorizationURL(scopes: string[], state?: string): Promise<PKCEResult> {
    return this.getAuthorizationURLPKCE(scopes, state);
  }

  async getAuthorizationURLPKCE(scopes: string[], state?: string): Promise<PKCEResult> {
    const stateOut = state || generateRandomValue();
    const codeVerifier = generateRandomValue();
    const codeChallenge = await computeS256Challenge(codeVerifier);
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: scopes.join(' '),
      state: stateOut,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return {
      url: `${this.issuer}/authorize?${params.toString()}`,
      state: stateOut,
      codeVerifier,
      codeChallenge,
    };
  }

  async exchangeCode(_code: string): Promise<TokenResponse> {
    throw new Error('PKCE code verifier is required; use exchangeCodePKCE');
  }

  async exchangeCodePKCE(code: string, codeVerifier: string): Promise<TokenResponse> {
    if (!codeVerifier) throw new Error('PKCE code verifier is required');
    return this.tokenRequest(new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: codeVerifier,
    }));
  }

  async clientCredentialsGrant(scopes?: string[]): Promise<TokenResponse> {
    const params = new URLSearchParams({ grant_type: 'client_credentials' });
    if (scopes?.length) params.set('scope', scopes.join(' '));
    return this.tokenRequest(params);
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    return this.tokenRequest(new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    }));
  }

  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const resp = await fetch(`${this.issuer}/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!resp.ok) throw new Error(`UserInfo failed: ${resp.status}`);
    return resp.json() as Promise<UserInfo>;
  }

  async introspectToken(token: string): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({ token });
    const headers = this.clientAuthentication(params);
    const resp = await fetch(`${this.issuer}/introspect`, { method: 'POST', headers, body: params });
    if (!resp.ok) throw new Error(`Introspect failed: ${resp.status}`);
    return resp.json() as Promise<Record<string, unknown>>;
  }

  async revokeToken(token: string): Promise<void> {
    const params = new URLSearchParams({ token });
    const headers = this.clientAuthentication(params);
    const resp = await fetch(`${this.issuer}/revoke`, { method: 'POST', headers, body: params });
    if (!resp.ok) throw new Error(`Revoke failed: ${resp.status}`);
  }

  private clientAuthentication(params: URLSearchParams): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (this.config.clientSecret) {
      const credentials = new TextEncoder().encode(`${this.config.clientId}:${this.config.clientSecret}`);
      headers.Authorization = `Basic ${bytesToBase64(credentials)}`;
    } else {
      params.set('client_id', this.config.clientId);
    }
    return headers;
  }

  private async tokenRequest(params: URLSearchParams): Promise<TokenResponse> {
    const headers = this.clientAuthentication(params);
    headers.Accept = 'application/json';
    const resp = await fetch(`${this.issuer}/token`, { method: 'POST', headers, body: params });
    const body = await resp.json() as TokenResponse | { error?: string; error_description?: string };
    if (!resp.ok) {
      const oauthError = body as { error?: string; error_description?: string };
      throw new Error(oauthError.error_description || oauthError.error || `Token request failed: ${resp.status}`);
    }
    return body as TokenResponse;
  }
}

function generateRandomValue(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

export async function computeS256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return base64UrlEncode(new Uint8Array(digest));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64UrlEncode(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
