/**
 * Configuration for the nyauth client.
 */
export interface NyAuthConfig {
  /** Base URL of the nyauth server (e.g., "https://auth.example.com") */
  issuer: string;
  /** OAuth 2.0 client ID */
  clientId: string;
  /** OAuth 2.0 client secret (optional for public clients) */
  clientSecret?: string;
  /** OAuth 2.0 redirect URI */
  redirectUri: string;
}

/**
 * Token response from the token endpoint.
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

/**
 * User information from the userinfo endpoint.
 */
export interface UserInfo {
  sub: string;
  preferred_username?: string;
  name?: string;
  email?: string;
  picture?: string;
}

/**
 * OIDC Discovery document.
 */
export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  introspection_endpoint?: string;
  scopes_supported?: string[];
  response_types_supported?: string[];
  grant_types_supported?: string[];
}

/**
 * Result of generating an authorization URL.
 */
export interface AuthorizationResult {
  url: string;
  state: string;
}

/**
 * Result of generating an authorization URL with PKCE.
 */
export interface PKCEResult extends AuthorizationResult {
  codeVerifier: string;
  codeChallenge: string;
}
