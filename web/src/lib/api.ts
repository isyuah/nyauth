import { PASSWORD_REQUIREMENT } from './password-policy';

const BASE = '';

export type UserRole = 'admin' | 'user';
export type UserStatus = 'active' | 'suspended' | 'pending';

export interface User {
  id: string;
  username: string;
  email?: string | null;
  email_verified_at?: string | null;
  display_name?: string | null;
  avatar_url?: string | null;
  role: UserRole;
  status: UserStatus;
  must_change_password?: boolean;
  last_login_at?: string | null;
  last_login_ip?: string | null;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at?: string;
}

export type UserCreationSource = 'bootstrap' | 'admin' | 'self_registration' | 'provider' | 'legacy';

export interface AdminUserReference {
  id: string;
  username: string;
  display_name?: string | null;
}

export interface AdminUserRegistrationSummary {
  status: 'pending' | 'completed' | 'released';
  invite_id?: string | null;
  expires_at: string;
  completed_at?: string | null;
  released_at?: string | null;
}

export interface AdminUserOverview {
  user: User;
  creation_source: UserCreationSource;
  created_by?: AdminUserReference | null;
  self_registration?: AdminUserRegistrationSummary | null;
}

export interface AdminUserSecurity {
  has_password: boolean;
  password_changed_at?: string | null;
  must_change_password: boolean;
  totp_available: boolean;
  totp_enrolled: boolean;
  recovery_codes_remaining: number;
  passkeys_available: boolean;
  passkeys_enrolled: number;
  passkey_clone_warnings: number;
  last_passkey_used_at?: string | null;
  mfa_required_for_admin: boolean;
  mfa_requirement_satisfied: boolean;
}

export interface AdminUserAuthorization {
  id: string;
  client_id: string;
  client_name: string;
  scopes: string[];
  allowed_claims: string[];
  granted_at: string;
  last_used_at?: string | null;
}

export interface AdminUserClientSummary {
  id: string;
  name: string;
  is_public: boolean;
  access_policy: string;
  grants: string[];
  scopes: string[];
  optional_scopes: string[];
  allowed_claims: string[];
  secret_hint?: string | null;
  secret_last_used_at?: string | null;
  created_at: string;
  updated_at: string;
}

export type SessionUser = User;

export interface SessionInfo {
  user: SessionUser;
  csrf_token: string;
  must_change_password: boolean;
  has_password: boolean;
  email_verified: boolean;
  authenticated_at?: string;
  session_expires_at?: string;
  session_idle_expires_at?: string;
  recent_authentication_expires_at?: string;
}

export type MFAMethod = 'totp' | 'recovery_code' | 'passkey';
export type CodeMFAMethod = Exclude<MFAMethod, 'passkey'>;
export type MFAPurpose = 'login' | 'reauthentication' | 'oauth_step_up';

export interface MFARequiredResponse {
  status: 'mfa_required';
  purpose: MFAPurpose;
  username: string;
  methods: MFAMethod[];
  csrf_token: string;
  expires_at: string;
  trusted_device_available?: boolean;
  trusted_device_ttl_seconds?: number;
  required_acr?: string;
}

export type LoginResponse = SessionInfo | MFARequiredResponse;
export type ReauthenticationResponse = SessionInfo | MFARequiredResponse;
export type ConsentStepUpResponse = MFARequiredResponse | { redirect_url: string };

export interface MFAStatus {
  totp_available: boolean;
  totp_enrolled: boolean;
  can_disable_totp: boolean;
  passkeys_available: boolean;
  passkeys_enrolled: number;
  recovery_codes_remaining: number;
  require_mfa_for_admins: boolean;
  required_for_current_user: boolean;
}

export interface TOTPEnrollment {
  secret: string;
  otpauth_uri: string;
}

export interface TOTPConfirmationResult extends SessionInfo {
  recovery_codes: string[];
}

export interface RecoveryCodesResult {
  recovery_codes: string[];
}

export interface SecuritySettings {
  revision: number;
  totp_enabled: boolean;
  passkeys_enabled: boolean;
  require_mfa_for_admins: boolean;
  trusted_devices_enabled: boolean;
  trusted_device_ttl: string;
}

export interface UpdateSecuritySettingsInput {
  expected_revision: number;
  totp_enabled: boolean;
  passkeys_enabled: boolean;
  require_mfa_for_admins: boolean;
  trusted_devices_enabled?: boolean;
  trusted_device_ttl?: string;
}

export interface WebAuthnOptionsResponse<TPublicKey> {
  ceremony_id: string;
  public_key: TPublicKey;
  mediation?: CredentialMediationRequirement;
  expires_at: string;
}

export type PasskeyAuthenticationOptions = WebAuthnOptionsResponse<PublicKeyCredentialRequestOptionsJSON>;
export type PasskeyRegistrationOptions = WebAuthnOptionsResponse<PublicKeyCredentialCreationOptionsJSON>;

export interface PasskeyCredential {
  id: string;
  name: string;
  transports: string[];
  aaguid?: string;
  attachment?: string;
  backup_eligible: boolean;
  backup_state: boolean;
  clone_warning: boolean;
  created_at: string;
  last_used_at?: string | null;
}

export interface PasskeyRegistrationResult extends SessionInfo {
  passkey: PasskeyCredential;
}

export function isMFARequiredResponse(response: unknown): response is MFARequiredResponse {
  return typeof response === 'object' && response !== null && 'status' in response
    && response.status === 'mfa_required';
}

export interface ExternalIdentity {
  id: string;
  user_id: string;
  provider: string;
  provider_type?: string | null;
  provider_display_name?: string | null;
  provider_icon_key?: string | null;
  external_id: string;
  external_username?: string | null;
  external_email?: string | null;
  created_at: string;
  updated_at?: string;
}

export interface ProviderSummary {
  name: string;
  display_name: string;
  icon_key: string;
  type: 'github' | 'google' | 'generic' | string;
}

export interface OAuthClient {
  id: string;
  name: string;
  homepage_uri: string;
  privacy_policy_uri: string;
  terms_of_service_uri: string;
  current_logo_id?: string | null;
  logo_url?: string | null;
  identity_revision: number;
  authorization_revision: number;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grants: string[];
  scopes: string[];
  optional_scopes: string[];
  allowed_claims: string[];
  is_public: boolean;
  access_policy?: ClientAccessPolicy;
  secret_hint?: string | null;
  secret_version: number;
  secret_rotated_at?: string | null;
  secret_last_used_at?: string | null;
  owner_id?: string | null;
  owner_username?: string | null;
  authorization_count?: number;
  success_count_7d?: number;
  failure_count_7d?: number;
  last_activity_at?: string | null;
  publisher_type: OAuthPublisherType;
  publisher_verification_status: OAuthPublisherVerificationStatus;
  publisher_verified_at?: string | null;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export type OAuthPublisherType = 'system_managed' | 'user_registered';
export type OAuthPublisherVerificationStatus = 'not_applicable' | 'unverified' | 'verified';

export type ClientAccessPolicy = 'open' | 'admins_only' | 'allowlist';

export interface ClientAccessUser {
  user_id: string;
  username: string;
  display_name: string;
  status: string;
  created_at: string;
}

export interface CreateClientInput {
  name: string;
  homepage_uri?: string;
  privacy_policy_uri?: string;
  terms_of_service_uri?: string;
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  grants: string[];
  scopes: string[];
  optional_scopes?: string[];
  allowed_claims?: string[];
  is_public: boolean;
  access_policy?: ClientAccessPolicy;
  owner_id?: string | null;
  metadata?: Record<string, string>;
}

export interface UpdateClientInput {
  name?: string;
  homepage_uri?: string;
  privacy_policy_uri?: string;
  terms_of_service_uri?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  grants?: string[];
  scopes?: string[];
  optional_scopes?: string[];
  allowed_claims?: string[];
  access_policy?: ClientAccessPolicy;
  metadata?: Record<string, string>;
}

export interface CreateClientResult extends OAuthClient {
  secret?: string;
}

export interface RotateClientSecretResult {
  client_id: string;
  secret: string;
  secret_hint: string;
  secret_version: number;
  secret_rotated_at: string;
}

export interface OAuthAuthorization {
  id: string;
  client_id: string;
  client_name: string;
  client_name_at_grant: string;
  logo_url?: string | null;
  homepage_uri?: string;
  privacy_policy_uri?: string;
  terms_of_service_uri?: string;
  homepage_uri_at_grant?: string;
  privacy_policy_uri_at_grant?: string;
  terms_of_service_uri_at_grant?: string;
  client_identity_revision: number;
  current_identity_revision: number;
  client_authorization_revision: number;
  current_authorization_revision: number;
  application_changed: boolean;
  reauthorization_required: boolean;
  scopes: string[];
  allowed_claims: string[];
  granted_at: string;
  last_used_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ExternalProvider {
  id: string;
  name: string;
  display_name: string;
  icon_key: string;
  type: 'github' | 'google' | 'generic' | string;
  client_id: string;
  scopes: string[];
  discovery_url?: string | null;
  authorization_url?: string | null;
  token_url?: string | null;
  userinfo_url?: string | null;
  enabled: boolean;
  import_avatar: boolean;
  avatar_allowed_hosts: string[];
  revision: number;
  metadata?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateProviderInput {
  name: string;
  display_name?: string;
  icon_key?: string;
  type: 'github' | 'google' | 'generic';
  client_id: string;
  client_secret: string;
  enabled: boolean;
  import_avatar?: boolean;
  avatar_allowed_hosts?: string[];
  scopes?: string[];
  discovery_url?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
}

export interface UpdateProviderInput {
  display_name?: string;
  icon_key?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  discovery_url?: string;
  authorization_url?: string;
  token_url?: string;
  userinfo_url?: string;
  enabled?: boolean;
  import_avatar?: boolean;
  avatar_allowed_hosts?: string[];
}

export interface ProviderTestResult {
  run_id: string;
  provider: string;
  provider_revision: number;
  type: string;
  configuration_valid: boolean;
  authorization_endpoint_valid: boolean;
  discovery_reachable?: boolean;
  latency_ms?: number;
  message: string;
  checks: ProviderDiagnosticCheck[];
  created_at: string;
}

export interface ProviderDiagnosticCheck {
  key: string;
  status: 'passed' | 'failed' | 'skipped';
  message: string;
  latency_ms: number;
}

export interface ProviderDiagnosticRun {
  id: string;
  provider_revision: number;
  mode: 'preflight' | 'interactive';
  result: 'success' | 'failure';
  checks: ProviderDiagnosticCheck[];
  created_at: string;
}

export type OAuthOperationFlow = 'authorization_code' | 'client_credentials' | 'refresh_token' | 'device_authorization';
export type OAuthOperationStage = 'authorization' | 'consent' | 'token' | 'device_authorization' | 'device_verification';

export interface OAuthClientInsights {
  client_id: string;
  days: number;
  timezone: 'UTC';
  totals: { success: number; failure: number; total: number; success_rate: number | null };
  active_authorizations: number;
  last_success_at?: string | null;
  last_failure_at?: string | null;
  trend: Array<{ day: string; success: number; failure: number }>;
  breakdown: Array<{ flow: OAuthOperationFlow; stage: OAuthOperationStage; success: number; failure: number }>;
}

export interface OAuthClientDiagnostic {
  id: string;
  occurred_at: string;
  request_id?: string | null;
  flow: OAuthOperationFlow;
  stage: OAuthOperationStage;
  reason: string;
  redirect_uri?: string | null;
  scopes: string[];
}

export interface OAuthClientListFilters {
  q?: string;
  type?: '' | 'public' | 'confidential';
  grant?: string;
  accessPolicy?: string;
  publisherStatus?: string;
  ownership?: '' | 'owned' | 'unowned';
  sort?: 'created_desc' | 'updated_desc' | 'name_asc' | 'activity_desc';
}

export interface OAuthDiagnosticFilters {
  flow?: string;
  stage?: string;
  reason?: string;
  page?: number;
  pageSize?: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export type AnnouncementStatus = 'draft' | 'published' | 'archived';
export type CommunicationSeverity = 'info' | 'warning' | 'critical';
export type AnnouncementAudience = 'authenticated' | 'admins';

export interface Announcement {
  id: string;
  status: AnnouncementStatus;
  severity: CommunicationSeverity;
  audience: AnnouncementAudience;
  title: string;
  summary: string;
  body_markdown?: string;
  body_html?: string;
  link_url?: string;
  pinned: boolean;
  starts_at?: string;
  ends_at?: string;
  published_at?: string;
  archived_at?: string;
  revision: number;
  created_at: string;
  updated_at: string;
  read?: boolean;
}

export interface AnnouncementInput {
  severity: CommunicationSeverity;
  audience: AnnouncementAudience;
  title: string;
  summary: string;
  body_markdown: string;
  link_url: string;
  pinned: boolean;
  starts_at: string | null;
  ends_at: string | null;
}

export interface UserNotification {
  id: string;
  type: string;
  severity: CommunicationSeverity;
  title: string;
  body_html: string;
  link_url?: string;
  source_type?: string;
  source_id?: string;
  created_at: string;
  read_at?: string;
  expires_at?: string;
}

export interface NotificationUnreadCount {
  unread_count: number;
  notification_count: number;
  announcement_count: number;
}

export type MessageCenterKind = 'all' | 'notification' | 'announcement';
export type MessageCenterReadState = 'all' | 'read' | 'unread';

export interface MessageCenterItem {
  kind: Exclude<MessageCenterKind, 'all'>;
  id: string;
  type?: string;
  severity: CommunicationSeverity;
  title: string;
  summary?: string;
  body_html?: string;
  link_url?: string;
  occurred_at: string;
  read: boolean;
  pinned?: boolean;
}

export interface MessageCenterFilters {
  page?: number;
  pageSize?: number;
  kind?: MessageCenterKind;
  read?: MessageCenterReadState;
  severity?: '' | CommunicationSeverity;
  query?: string;
  from?: string;
  to?: string;
}

export interface ClientQuota {
  quota_used: number;
  quota_limit: number;
  quota_override: number | null;
}

export interface ClientQuotaPage<T> extends PaginatedResponse<T>, ClientQuota {}

export type OAuthGrantType = 'authorization_code' | 'urn:ietf:params:oauth:grant-type:device_code' | 'refresh_token' | 'client_credentials';
export type OAuthScope = string;
export type OAuthAssignmentPolicy = 'self_service' | 'admin_only';
export type OAuthRiskLevel = 'low' | 'personal_data' | 'sensitive';

export interface OAuthScopeDefinition {
  display_name: string;
  description: string;
  claims: string[];
  assignment_policy: OAuthAssignmentPolicy;
  risk_level: OAuthRiskLevel;
}

export interface OAuthClientPolicy {
  self_service_client_creation_enabled: boolean;
  public_clients_enabled: boolean;
  allowed_grant_types: OAuthGrantType[];
  allowed_scopes: OAuthScope[];
  scope_definitions: Record<string, OAuthScopeDefinition>;
  claim_assignment_policies: Record<string, OAuthAssignmentPolicy>;
  max_redirect_uris: number;
  max_post_logout_redirect_uris: number;
}

export interface OAuthSettings extends OAuthClientPolicy {
  revision: number;
}

export interface UpdateOAuthSettingsInput extends OAuthClientPolicy {
  expected_revision: number;
}

export interface MyClientPage extends ClientQuotaPage<OAuthClient> {
  client_policy: OAuthClientPolicy;
}

export interface DashboardStats {
  user_count: number;
  app_count: number;
  login_count_7d: number;
  active_sessions: number;
  failed_logins_7d: number;
  pending_registrations: number;
  completed_registrations_7d: number;
  registration_completion_rate_30d: number | null;
  mail_backlog: number;
  mail_failures_24h: number;
  smtp_circuit_state: 'closed' | 'open';
  mail_stats_available_from: string;
  refreshed_at: string;
}

export interface LoginTrend {
  labels: string[];
  values: number[];
}

export type StatsTrendDays = 7 | 30 | 90;

export interface RegistrationTrendPoint {
  day: string;
  registrations_started: number;
  registrations_completed: number;
  registrations_expired: number;
  invites_reserved: number;
  invites_consumed: number;
  invites_released: number;
}

export interface RegistrationTrend {
  timezone: 'UTC';
  points: RegistrationTrendPoint[];
}

export interface MailTrendPoint {
  day: string;
  enqueued: number;
  sent: number;
  other_failures: number;
  rejected: number;
  expired: number;
}

export interface MailTrend {
  timezone: 'UTC';
  available_from: string;
  points: MailTrendPoint[];
}

export interface RecentLogin {
  username: string;
  role?: UserRole;
  result: string;
  ip: string;
  time: string;
}

export interface ConsentRequest {
  challenge: string;
  flow: 'authorization_code' | 'device_authorization';
  client_name: string;
  client_id: string;
  scopes: string[];
  permissions: ConsentPermission[];
  redirect_uri: string;
  redirect_origin: string;
  publisher_type: OAuthPublisherType;
  verification_status: OAuthPublisherVerificationStatus;
  logo_url?: string | null;
  homepage_uri?: string;
  privacy_policy_uri?: string;
  terms_of_service_uri?: string;
  previously_authorized: boolean;
  application_changed: boolean;
  reauthorization_required: boolean;
  new_scopes: string[];
  new_claims: string[];
  step_up_required: boolean;
  required_acr?: string;
  max_age?: number | null;
}

export interface ConsentPermission {
  scope: string;
  display_name: string;
  description: string;
  risk_level: OAuthRiskLevel;
  required: boolean;
  claims: string[];
  previously_granted: boolean;
  newly_requested: boolean;
}

export interface AuditLog {
  id: string;
  event: string;
  actor_id?: string | null;
  actor_name?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  ip_address?: string | null;
  user_agent?: string | null;
  result: string;
  risk_level: string;
  details?: Record<string, unknown>;
  created_at: string;
}

export interface AuditLogFilters {
  page?: number;
  pageSize?: number;
  event?: string;
  events?: string[];
  result?: string;
  risk?: string;
  actor?: string;
  target?: string;
  subjectUserId?: string;
  targetType?: string;
  targetId?: string;
  ip?: string;
  from?: string;
  to?: string;
}

export interface AuditLogOptions {
  events: string[];
  results: string[];
  risks: string[];
  target_types: string[];
}

const auditLogFilterParameters = {
  event: 'event',
  result: 'result',
  risk: 'risk',
  actor: 'actor',
  target: 'target',
  subjectUserId: 'subject_user_id',
  targetType: 'target_type',
  targetId: 'target_id',
  ip: 'ip',
  from: 'from',
  to: 'to',
} as const;

export function buildAuditLogSearchParams(filters: AuditLogFilters = {}, includePagination = true): URLSearchParams {
  const params = new URLSearchParams();
  if (includePagination) {
    params.set('page', String(filters.page || 1));
    params.set('page_size', String(filters.pageSize || 20));
  }
  const events = filters.events?.length ? filters.events : filters.event ? [filters.event] : [];
  for (const event of events) {
    if (event) params.append('event', event);
  }
  for (const [filterKey, parameter] of Object.entries(auditLogFilterParameters) as Array<[keyof typeof auditLogFilterParameters, string]>) {
    if (filterKey === 'event') continue;
    const value = filters[filterKey];
    if (value) params.set(parameter, value);
  }
  return params;
}

export function buildAuditLogExportURL(filters: AuditLogFilters, format: 'ndjson' | 'cef', limit = 50_000): string {
  const params = buildAuditLogSearchParams(filters, false);
  params.set('format', format);
  params.set('limit', String(limit));
  return `/api/admin/audit-logs/export?${params}`;
}

export interface BrowserSession {
  id: string;
  current: boolean;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  last_seen_at: string;
  authenticated_at: string;
  session_expires_at: string;
  session_idle_expires_at: string;
  recent_authentication_expires_at: string;
}

export interface TrustedDevice {
  id: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
  last_used_at: string;
  expires_at: string;
  current: boolean;
}

export interface TrustedDevicesResponse {
  enabled: boolean;
  items: TrustedDevice[];
}

export interface LoginHistoryEntry {
  id: string;
  result: 'success' | 'failure' | string;
  authentication_method: string;
  second_factor?: string;
  provider?: string;
  ip_address?: string;
  user_agent?: string;
  created_at: string;
}

export interface Branding {
  title: string;
	primary_color: string;
	primary_text_color: PrimaryTextColor;
	light_logo_url: string;
	dark_logo_url: string;
	favicon_url: string;
}

export type Theme = 'light' | 'dark' | 'system';
export type ResolvedTheme = Exclude<Theme, 'system'>;
export type PrimaryTextColor = 'auto' | 'white' | 'black';

export interface BrandingSettings extends Branding {
	revision: number;
}

export interface UpdateBrandingSettingsInput extends Branding {
	expected_revision: number;
}

export type SiteBannerSeverity = 'info' | 'warning' | 'critical';

export interface EmailTemplateContent {
  subject: string;
  heading: string;
  body: string;
  button_label?: string;
}

export interface EmailTemplateSettings {
  footer: string;
  templates: Record<string, EmailTemplateContent>;
}

export interface EmailTemplateVariableRules {
  subject: string[];
  heading: string[];
  body: string[];
  button_label: string[];
  required_body: string[];
}

export interface SiteBannerSettings {
  version: number;
  enabled: boolean;
  severity: SiteBannerSeverity;
  title: string;
  message: string;
  dismissible: boolean;
  starts_at: string | null;
  ends_at: string | null;
}

export interface CommunicationsSettings {
  revision: number;
  email: EmailTemplateSettings;
  site_banner: SiteBannerSettings;
  template_variables: Record<string, EmailTemplateVariableRules>;
}

export interface UpdateCommunicationsSettingsInput {
  expected_revision: number;
  email: EmailTemplateSettings;
  site_banner: SiteBannerSettings;
}

export interface EmailTemplatePreview {
  subject: string;
  text_body: string;
  html_body: string;
}

export interface SiteBannerMarkdownPreview {
  html: string;
}

export interface PublicSiteBanner {
  version: number;
  severity: SiteBannerSeverity;
  title: string;
  message_html: string;
  dismissible: boolean;
  ends_at?: string;
}

export interface PublicSiteBannerResponse {
  site_banner: PublicSiteBanner | null;
  next_change_at?: string;
}

export type LogLevel = 'info' | 'warn' | 'error';
export type EffectiveLogLevel = LogLevel | 'debug';
export type OTLPRuntimeMode = 'fallback' | 'active' | 'disabled';
export type OperationalAlertStatus = 'pending' | 'ok' | 'unavailable' | string;

export interface OperationalAlertThresholds {
  mail_backlog_count: number;
  mail_oldest_pending_age: string;
  audit_outbox_backlog_count: number;
  audit_oldest_pending_age: string;
  avatar_cleanup_pending_count: number;
}

export interface ObservabilityPolicy {
  log_level: LogLevel;
  debug_until?: string | null;
  alerts: OperationalAlertThresholds;
}

export interface OperationalAlert {
  code: 'mail_backlog' | 'mail_oldest_pending' | 'audit_outbox_backlog' | 'audit_oldest_pending' | 'avatar_cleanup_pending' | string;
  current: number;
  threshold: number;
  unit: 'count' | 'seconds' | string;
}

export interface OperationalAlertSnapshot {
  status: OperationalAlertStatus;
  checked_at?: string;
  active: OperationalAlert[];
}

export interface OTLPConfigSummary {
  id?: string;
  revision?: number;
  endpoint: string;
  export_interval: string;
  timeout: string;
  authorization_configured: boolean;
  created_at?: string;
}

export interface OTLPRuntimeStatus {
  configured: boolean;
  available: boolean;
  last_success_at?: string;
  last_error_at?: string;
  last_error_code?: string;
}

export interface OTLPCandidateTestEvidence {
  result: 'success' | 'failure';
  error_code?: string;
  tested_at: string;
  valid_until?: string;
  activation_eligible: boolean;
}

export interface OTLPSettings {
  mode: OTLPRuntimeMode;
  state_revision: number;
  active?: OTLPConfigSummary;
  candidate?: OTLPConfigSummary;
  candidate_test?: OTLPCandidateTestEvidence;
  previous?: OTLPConfigSummary;
  effective?: OTLPConfigSummary;
  runtime: OTLPRuntimeStatus;
}

export interface ObservabilitySettings {
  revision: number;
  observability: ObservabilityPolicy;
  effective_log_level: EffectiveLogLevel;
  otlp: OTLPSettings;
  alerts: OperationalAlertSnapshot;
}

export interface UpdateObservabilitySettingsInput {
  expected_revision: number;
  observability: ObservabilityPolicy;
}

export interface SaveOTLPCandidateInput {
  expected_revision: number;
  endpoint: string;
  authorization?: string;
  export_interval: string;
  timeout: string;
}

export interface SaveOTLPCandidateResult {
  candidate: OTLPConfigSummary;
  state_revision: number;
}

export interface TestOTLPCandidateResult {
  result: 'success' | 'failure';
  error_code?: string;
  state_revision: number;
  tested_at: string;
}

export interface OTLPMutationResult {
  state_revision: number;
  mode: OTLPRuntimeMode;
}

export type RegistrationMode = 'closed' | 'invite_only' | 'open';

export interface RegistrationOptions {
  available: boolean;
  mode: RegistrationMode;
  require_email_verification: boolean;
  allowed_email_domains: string[];
}

export type ServiceCapability =
  | 'self_registration'
  | 'account_mutations'
  | 'admin_mutations'
  | 'auth_issuance'
  | 'mail_delivery'
  | 'media_writes';

export type ServiceOperatingState = 'normal' | 'restricted' | 'authentication_paused' | 'full_pause';

export interface ServiceStatus {
  status: ServiceOperatingState;
  paused_capabilities: ServiceCapability[];
  public_message: string;
  expires_at: string | null;
  retry_after_seconds: number;
}

export interface ServiceControlInstance {
  instance_id: string;
  version: string;
  started_at: string;
  heartbeat_at: string;
  loaded_revision: number;
  applied_revision: number;
}

export interface OperationsSettings extends ServiceStatus {
  revision: number;
  internal_reason: string;
  updated_at: string;
  updated_by: string | null;
  application_status: 'applied' | 'applying';
  active_instances: number;
  applied_instances: number;
  instances: ServiceControlInstance[];
}

export interface UpdateOperationsSettingsInput {
  expected_revision: number;
  paused_capabilities: ServiceCapability[];
  public_message: string;
  internal_reason: string;
  expires_at: string | null;
}

export interface ProtectionLoginSettings {
  enabled: boolean;
  window: string;
  identity_limit: number;
  ip_limit: number;
  passkey_ceremony_ip_limit: number;
}

export interface ProtectionAccountSettings {
  enabled: boolean;
  window: string;
  subject_limit: number;
  ip_limit: number;
}

export interface ProtectionAvatarSettings {
  enabled: boolean;
  window: string;
  user_limit: number;
  ip_limit: number;
}

export interface ProtectionMailSettings {
  enabled: boolean;
  window: string;
  save_limit: number;
  test_limit: number;
  activate_limit: number;
  rollback_limit: number;
  disable_limit: number;
  ip_limit: number;
}

export interface ProtectionSettings {
  revision: number;
  login: ProtectionLoginSettings;
  account: ProtectionAccountSettings;
  avatar: ProtectionAvatarSettings;
  mail: ProtectionMailSettings;
  owned_client_default_limit: number;
}

export interface UpdateProtectionSettingsInput {
  expected_revision: number;
  login: ProtectionLoginSettings;
  account: ProtectionAccountSettings;
  avatar: ProtectionAvatarSettings;
  mail: ProtectionMailSettings;
  owned_client_default_limit: number;
  disable_confirmation?: string;
}

export interface LifecycleSettings {
  revision: number;
  session_absolute_ttl: string;
  session_idle_ttl: string;
  max_concurrent_sessions: number;
  recent_authentication_ttl: string;
  access_token_ttl: string;
  refresh_token_ttl: string;
  authorization_code_ttl: string;
  audit_retention_days: number;
}

export interface UpdateLifecycleSettingsInput {
  expected_revision: number;
  session_absolute_ttl: string;
  session_idle_ttl: string;
  max_concurrent_sessions: number;
  recent_authentication_ttl: string;
  access_token_ttl: string;
  refresh_token_ttl: string;
  authorization_code_ttl: string;
  audit_retention_days: number;
  retention_confirmation?: string;
}

export interface RegistrationSettings {
	revision: number;
  mode: RegistrationMode;
  require_email_verification: boolean;
  allowed_email_domains: string[];
  pending_registration_ttl: string;
  invite_default_ttl: string;
  invite_default_max_uses: number;
}

export interface UpdateRegistrationSettingsInput {
	expected_revision: number;
	mode: RegistrationMode;
	require_email_verification: boolean;
	allowed_email_domains: string[];
	pending_registration_ttl: string;
	invite_default_ttl: string;
	invite_default_max_uses: number;
}

export interface RegisterInput {
  username: string;
  email: string;
  password: string;
  invite_code?: string;
	 human_verification?: HumanVerificationProof;
}

export type HumanVerificationProvider = 'turnstile';
export type HumanVerificationAction = 'register' | 'login' | 'password_reset' | 'email_verification_resend' | 'provider_login' | 'admin_test';
export type HumanVerificationLoginMode = 'off' | 'adaptive' | 'always';

export interface HumanVerificationProof {
  token: string;
  idempotency_key: string;
}

export interface HumanVerificationChallenge {
  enabled: boolean;
  required: boolean;
  available: boolean;
  provider?: HumanVerificationProvider;
  site_key?: string;
  widget_mode?: 'managed' | 'non-interactive' | 'invisible';
  action: HumanVerificationAction;
}

export interface HumanVerificationPolicy {
  registration: boolean;
  login_mode: HumanVerificationLoginMode;
  login_trigger_after: number;
  password_reset: boolean;
  email_verification_resend: boolean;
  provider_login: boolean;
}

export interface HumanVerificationVersion {
  id: string;
  revision: number;
  provider: HumanVerificationProvider;
  site_key: string;
  widget_mode: 'managed' | 'non-interactive' | 'invisible';
  secret_configured: boolean;
  created_by?: string | null;
  created_at: string;
}

export interface HumanVerificationTestRecord {
  id: string;
  version_id: string;
  result: 'success' | 'failure';
  error_code?: string | null;
  tested_by?: string | null;
  created_at: string;
}

export interface HumanVerificationState {
  mode: 'active' | 'disabled';
  active_version_id?: string | null;
  candidate_version_id?: string | null;
  previous_version_id?: string | null;
  policy: HumanVerificationPolicy;
  revision: number;
  updated_at: string;
}

export interface HumanVerificationSettings extends HumanVerificationState {
  active?: HumanVerificationVersion | null;
  candidate?: HumanVerificationVersion | null;
  previous?: HumanVerificationVersion | null;
  candidate_last_test?: HumanVerificationTestRecord | null;
  runtime: {
    mode: 'active' | 'disabled';
    configured: boolean;
    available: boolean;
    provider?: HumanVerificationProvider;
    state_revision: number;
  };
}

export interface SaveHumanVerificationCandidateInput {
  expected_revision: number;
  provider: HumanVerificationProvider;
  site_key: string;
  widget_mode: 'managed' | 'non-interactive' | 'invisible';
  secret?: string;
}

export interface HumanVerificationCandidateResult {
  version: HumanVerificationVersion;
  state: HumanVerificationState;
}

export interface HumanVerificationTestResult {
  record: HumanVerificationTestRecord;
  state: HumanVerificationState;
}

export interface Invite {
  id: string;
  created_by: string | null;
  note: string;
  max_uses: number;
  used_count: number;
  reserved_count: number;
  expires_at: string;
  revoked_at?: string | null;
  created_at: string;
  status: 'active' | 'expired' | 'exhausted' | 'revoked' | string;
}

export interface CreateInviteResult extends Invite {
  code: string;
  register_url: string;
}

export interface RegisterResult {
  status: 'pending_verification' | 'registered';
  verification_expires_at?: string;
}

export type MailTLSMode = 'starttls' | 'implicit' | 'plain';
export type MailRuntimeMode = 'fallback' | 'active' | 'disabled' | string;
export type MailCircuitState = 'closed' | 'open' | string;
export type MailErrorCategory = 'configuration' | 'authentication' | 'tls' | 'transport' | 'recipient' | 'unknown' | string;

export interface MailConfig {
  source: 'environment' | 'database' | string;
  id?: string;
  revision?: number;
  host: string;
  port: number;
  username: string;
  tls_mode: MailTLSMode;
  from_address: string;
  from_name: string;
  public_base_url: string;
  connect_timeout: string;
  send_timeout: string;
  password_configured: boolean;
  created_by?: string;
  created_at?: string;
}

export interface MailCircuit {
  state: MailCircuitState;
  open_category?: MailErrorCategory;
  open_reason?: string;
  opened_at?: string;
  next_probe_at?: string;
  transport_failure_count: number;
}

export interface MailSettings {
  mode: MailRuntimeMode;
  configured: boolean;
  available: boolean;
  state_revision: number;
  circuit: MailCircuit;
  active?: MailConfig;
  candidate?: MailConfig;
  previous?: MailConfig;
}

export interface SaveMailCandidateInput {
  expected_revision: number;
  host: string;
  port: number;
  username: string;
  password?: string;
  tls_mode: MailTLSMode;
  from_address: string;
  from_name: string;
  public_base_url: string;
  connect_timeout: string;
  send_timeout: string;
}

export interface SaveMailCandidateResult {
  candidate: MailConfig;
  state_revision: number;
}

export interface MailTestResult {
  result: 'success' | 'failure';
  error_category?: MailErrorCategory;
  tested_at: string;
  state_revision: number;
}

export interface MailMutationResult {
  status: 'activated' | 'rolled_back' | 'disabled' | string;
  state_revision: number;
}

export interface MediaStorageProfileSettings {
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  path_style: boolean;
}

export interface MediaStorageProfile {
  id?: string;
  backend: 'local' | 's3' | string;
  settings?: MediaStorageProfileSettings;
  credentials_configured: boolean;
  session_token_configured?: boolean;
  created_by?: string;
  created_by_name?: string;
  created_at?: string;
  tested_at?: string;
  test_result?: 'success' | 'failure';
  test_error_category?: string;
  test_error?: string;
}

export interface MediaStorageMigration {
  id: string;
  source_profile_id?: string;
  source_backend: string;
  target_profile_id?: string;
  target_backend: 'local' | 's3' | string;
  status: 'pending' | 'running' | 'applying' | 'completed' | 'failed' | string;
  total_count: number;
  copied_count: number;
  completed_count: number;
  failed_count: number;
  created_by?: string;
  created_by_name: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  failed_at?: string;
  last_error?: string;
  updated_at: string;
}

export interface MediaStorageSettings {
  mode: 'fallback' | 'dynamic' | string;
  revision: number;
  available: boolean;
  active?: MediaStorageProfile;
  fallback?: MediaStorageProfile;
  candidate?: MediaStorageProfile;
  previous?: MediaStorageProfile;
  migration?: MediaStorageMigration;
}

export interface SaveMediaStorageCandidateInput extends MediaStorageProfileSettings {
  expected_revision: number;
  access_key_id: string;
  secret_access_key: string;
  session_token: string;
}

export type ComponentStatus = 'ok' | 'degraded' | 'unavailable' | string;

export interface SystemStatus {
  status: ComponentStatus;
  operating_state?: ServiceOperatingState;
  version: string;
  disabled_rate_limit_groups: Array<'login' | 'account' | 'avatar' | 'mail'>;
  schema: {
    status: ComponentStatus;
    version: number;
    required_version: number;
  };
  services: {
    postgresql: { status: ComponentStatus; latency_ms: number };
    redis: { status: ComponentStatus; latency_ms: number };
    providers: { status: ComponentStatus; latency_ms: number; snapshot_revision: number };
    jwk: { status: ComponentStatus; latency_ms: number };
    mail: {
      status: ComponentStatus;
      mode: MailRuntimeMode;
      configured: boolean;
      available: boolean;
      circuit_state: MailCircuitState;
    };
    media: {
      status: ComponentStatus;
      backend: 'local' | 's3' | string;
      configured: boolean;
      last_error_at?: string;
    };
    observability: {
      status: ComponentStatus;
      log_level: EffectiveLogLevel;
      debug_until?: string;
      otlp_mode: OTLPRuntimeMode;
      otlp_configured: boolean;
      otlp_available: boolean;
      last_export_at?: string;
      last_error_at?: string;
      last_error_code?: string;
    };
    human_verification: {
      status: ComponentStatus;
      mode: 'active' | 'disabled';
      configured: boolean;
      available: boolean;
      provider?: HumanVerificationProvider;
    };
  };
  operational_alerts: OperationalAlertSnapshot;
  active_signing_key?: {
    kid: string;
    status: ComponentStatus;
    signing_started_at: string;
    next_rotation_at: string;
  };
}

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  device_authorization_endpoint?: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
}

export interface CreateUserInput {
  username: string;
  email?: string;
  password: string;
  display_name?: string;
}

export interface UpdateUserInput {
  username?: string;
  email?: string | null;
  display_name?: string | null;
  status?: UserStatus;
  role?: UserRole;
  metadata?: Record<string, string>;
}

export interface APIErrorResponse {
  code?: string;
  error?: string;
  error_description?: string;
  message?: string;
  missing_admins?: unknown;
  [key: string]: unknown;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly retryAfter?: number,
    readonly serverMessage: string = message,
    readonly response?: APIErrorResponse,
    readonly code: string = response?.code || 'request_failed',
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function missingAdminsFromError(cause: unknown): string[] {
  if (!(cause instanceof ApiError) || !Array.isArray(cause.response?.missing_admins)) return [];
  return cause.response.missing_admins.filter((value): value is string => typeof value === 'string' && value.trim() !== '');
}

export function humanVerificationChallengeFromError(cause: unknown): HumanVerificationChallenge | null {
  if (!(cause instanceof ApiError) || cause.code !== 'human_verification.required') return null;
  const challenge = cause.response?.challenge as Partial<HumanVerificationChallenge> | undefined;
  const actions: HumanVerificationAction[] = ['register', 'login', 'password_reset', 'email_verification_resend', 'provider_login', 'admin_test'];
  const widgetModes: NonNullable<HumanVerificationChallenge['widget_mode']>[] = ['managed', 'non-interactive', 'invisible'];
  if (!challenge || challenge.enabled !== true || challenge.required !== true || challenge.available !== true
    || challenge.provider !== 'turnstile' || typeof challenge.site_key !== 'string' || challenge.site_key.trim() === ''
    || !actions.includes(challenge.action as HumanVerificationAction)
    || !widgetModes.includes(challenge.widget_mode as NonNullable<HumanVerificationChallenge['widget_mode']>)) return null;
  return challenge as HumanVerificationChallenge;
}

const PASSWORD_POLICY_ERROR = 'password must be valid utf-8 and 12 to 1024 bytes';
const API_ERROR_TRANSLATIONS: Record<string, string> = {
  'invalid credentials': '认证凭据不正确',
  'current password is incorrect': '当前密码不正确',
  'authentication required': '登录状态已失效，请重新登录',
  'recent authentication is required': '请先完成近期身份验证',
  'password reauthentication is unavailable': '此账户无法使用密码重新认证',
  'password login is not available for this account': '此账户无法使用密码登录',
  'a local password is already configured': '此账户已设置本地密码',
  'reauthentication failed': '重新认证失败，请稍后重试',
  'reauthentication session could not be updated': '重新认证成功，但会话更新失败，请重试',
  'csrf_validation_failed': '安全校验失败，请刷新页面后重试',
  'invalid csrf token': '安全校验失败，请刷新页面后重试',
  'password change required': '请先修改密码后再继续',
  'human verification is required': '请完成人机验证后继续',
  'human verification failed': '人机验证未通过，请重新尝试',
  'human verification is temporarily unavailable': '人机验证暂时不可用，请稍后重试',
  'human verification provider is unavailable': 'Cloudflare Turnstile 暂时不可用',
  'human verification test was rejected': '候选人机验证配置未能通过测试',
  'human verification settings are unavailable': '人机验证设置暂时不可用',
  'human verification settings revision conflict': '人机验证设置已被其他管理员修改',
  'human verification candidate changed': '人机验证候选配置已变化，请重新加载',
  'a human verification secret is required': '首次配置必须填写 Secret Key',
  'a successful human verification candidate test is required': '激活前必须完成一次成功的候选配置测试',
  'the successful human verification candidate test has expired': '候选配置测试已超过十分钟，请重新测试',
  'no previous human verification configuration is available': '没有可回滚的人机验证配置',
  'human verification is already disabled': '人机验证已经处于禁用状态',
  'email verification is required before signing in': '邮箱尚未验证，请先完成验证邮件中的确认再登录',
  'registration is closed': '当前未开放注册',
  'invite code is required': '需要邀请码才能注册',
  'invalid or expired invite code': '邀请码无效或已失效',
  'username or email is already taken': '用户名或邮箱已被使用',
  'username is already taken': '用户名已被其他账户使用',
  'email is already taken': '邮箱已被其他账户使用',
  'email domain is not allowed': '该邮箱域名不允许注册',
  'too many registration attempts': '注册尝试过于频繁，请稍后再试',
  'registration is temporarily unavailable': '注册功能暂时不可用，请稍后重试',
  'registration temporarily unavailable': '注册功能暂时不可用，请稍后重试',
  'registration requires email delivery, which is not configured': '注册功能暂不可用：邮件服务未配置',
  'mail settings are temporarily unavailable': '邮件设置暂时不可用，请稍后重试',
  'mail configuration is invalid': 'SMTP 配置无效，请检查各字段和密码设置',
  'mail configuration version was not found': '邮件配置版本不存在，请重新加载',
  'mail settings changed; reload and try again': '邮件设置已被其他管理员修改，请重新加载后再试',
  'a successful candidate test is required': '激活前必须先成功发送候选配置的测试邮件',
  'the successful candidate test has expired': '候选配置的成功测试已过期，请重新发送测试邮件',
  'no previous mail configuration is available': '没有可回滚的上一版邮件配置',
  'mail is already disabled': '邮件服务已经处于禁用状态',
  'close self-registration before disabling mail': '禁用邮件服务前必须先关闭自助注册',
  'too many mail settings operations': '邮件设置操作过于频繁，请稍后重试',
  'a verified administrator email is required for template tests': '发送模板测试邮件前，请先验证当前管理员的邮箱地址',
  "test recipient must match the administrator's verified email": '测试邮件只能发送到当前管理员已验证的邮箱地址',
  'mail delivery is unavailable': '邮件投递当前不可用，请检查 SMTP 状态后重试',
  'test email could not be delivered': '测试邮件发送失败，请检查 SMTP 状态和收件地址后重试',
  'connect_timeout must be a valid duration': '连接超时必须是有效时长，例如 10s',
  'send_timeout must be a valid duration': '发送超时必须是有效时长，例如 30s',
  'plain smtp is forbidden in production': '生产环境禁止使用明文 SMTP',
  'public_base_url must use https in production': '生产环境的公开地址必须使用 HTTPS',
  'email is invalid': '邮箱地址格式无效',
  'mfa challenge expired': '多因素验证已过期，请重新登录',
  'mfa challenge temporarily unavailable': '多因素验证暂时不可用，请稍后重试',
  'mfa verification temporarily unavailable': '多因素验证暂时不可用，请稍后重试',
  'too many mfa attempts': '验证尝试过于频繁，请稍后再试',
  'invalid mfa code': '验证码或恢复码不正确',
  'invalid totp code': '动态验证码不正确',
  'unsupported mfa method': '当前验证方式不可用，请刷新页面重试',
  'account changed; sign in again': '账户安全状态已变化，请重新登录',
  'mfa enrollment is required; contact an administrator': '管理员策略要求启用多因素验证，请联系管理员协助完成设置',
  'totp enrollment is disabled': '管理员已关闭动态验证码注册',
  'totp is already enrolled': '动态验证码已经启用',
  'totp enrollment must be restarted': '本次设置已失效，请重新开始启用动态验证码',
  'totp is not enrolled': '尚未启用动态验证码',
  'mfa is required for active administrators': '管理员策略要求保留多因素验证，当前无法停用',
  'all active administrators must enroll mfa before it can be required': '仍有管理员未启用多因素验证，暂时无法强制执行',
  'totp must remain enabled while administrator mfa is required': '要求管理员启用多因素验证时，必须同时开放动态验证码功能',
  'passkey login temporarily unavailable': 'Passkey 登录暂时不可用，请稍后重试',
  'passkey ceremony temporarily unavailable': 'Passkey 安全验证暂时不可用，请稍后重试',
  'passkey verification temporarily unavailable': 'Passkey 验证暂时不可用，请稍后重试',
  'passkey reauthentication temporarily unavailable': 'Passkey 重新认证暂时不可用，请稍后重试',
  'passkey registration temporarily unavailable': 'Passkey 注册暂时不可用，请稍后重试',
  'passkey registered; please sign in again': 'Passkey 已注册，但当前会话无法继续使用，请重新登录',
  'passkey removed; please sign in again': 'Passkey 已删除，但当前会话无法继续使用，请重新登录',
  'passkey verification failed': 'Passkey 验证失败，请重试',
  'passkey registration could not be verified': '无法验证这枚 Passkey，请重新注册',
  'passkey enrollment is disabled': '管理员已关闭新的 Passkey 注册',
  'this passkey is already registered': '这枚 Passkey 已经注册',
  'no passkey is registered': '当前账户尚未注册 Passkey',
  'passkey not found': 'Passkey 不存在或已被删除',
  'passkey name must contain 1 to 64 characters': 'Passkey 名称须为 1 至 64 个字符',
  'add a password, provider identity, or another passkey before removing this passkey': '请先添加密码、外部身份或另一枚 Passkey，再删除当前 Passkey',
  'webauthn ceremony id is required': 'Passkey 验证状态缺失，请重新开始',
  'webauthn ceremony expired': 'Passkey 验证已过期，请重新开始',
  'webauthn ceremony is invalid': 'Passkey 验证状态无效，请重新开始',
  'too many passkey ceremonies': 'Passkey 操作过于频繁，请稍后重试',
  'avatar image exceeds 8 mib': '头像文件不能超过 8 MiB',
  'avatar media type must be jpeg, png, or static webp': '仅支持 JPEG、PNG 或静态 WebP 头像',
  'animated webp avatars are not supported': '不支持动态 WebP 头像',
  'avatar image dimensions are invalid': '头像尺寸或总像素数超出限制',
  'user avatar upload must be square after browser crop': '头像必须先裁剪为正方形',
  'too many avatar operations': '头像操作过于频繁，请稍后重试',
  'avatar operation is temporarily unavailable': '头像操作暂时不可用，请稍后重试',
  'avatar storage is temporarily unavailable': '头像存储暂时不可用，请稍后重试',
  'media operation is temporarily unavailable': '图片操作暂时不可用，请稍后重试',
  'media processing is temporarily unavailable': '图片处理当前繁忙，请稍后重试',
  'too many media operations': '图片操作过于频繁，请稍后重试',
  'media settings are temporarily unavailable': '媒体存储设置暂时不可用，请稍后重试',
  'media storage configuration is invalid': '对象存储配置无效，请检查 endpoint、区域、bucket 和凭据',
  'media settings changed; reload and try again': '媒体存储设置已被其他管理员修改，请重新加载',
  'media storage candidate was not found': '对象存储候选配置不存在，请重新保存',
  'a recent successful media storage test is required': '迁移前必须在十分钟内成功完成真实对象存储测试',
  'a media storage migration is already active': '已有媒体存储迁移正在进行',
  'media storage migration was not found': '媒体存储迁移不存在或当前不可重试',
  'media writes must be paused before migration': '迁移前必须先完成媒体写入排空',
  'active instances are still preparing the media storage candidate': '仍有运行实例尚未加载候选配置，请稍后重试',
  'media writes are still draining; retry after service control is applied': '媒体写入仍在排空，请稍后重试启动迁移',
  'clear the current maintenance expiry before starting media migration': '迁移期间不能自动恢复媒体写入，请先清除当前维护状态的到期时间',
  'too many media settings operations': '媒体存储设置操作过于频繁，请稍后重试',
  'application limit reached': '已达到该账户的应用配额上限',
  'self-service client creation is disabled': '管理员已关闭用户自助创建客户端',
  'oauth client policy changed; reload and retry': 'OAuth 客户端策略已更新，请重新加载后再试',
  'publisher verification is not applicable to system-managed clients': '系统管理客户端不需要发布者审核',
  'publisher verification status is unchanged': '发布者可信状态已经是目标状态',
  'application not found': '应用不存在，或您没有管理权限',
  'failed to update application': '应用保存失败，请重新加载后重试',
  'logo was updated but the application could not be reloaded': 'Logo 已上传，但应用信息刷新失败，请重新加载页面',
  'logo was removed but the application could not be reloaded': 'Logo 已删除，但应用信息刷新失败，请重新加载页面',
  'client_changed_restart_authorization': '应用配置在授权期间已变更，请返回应用重新发起授权',
  'failed to update publisher verification': '发布者可信状态更新失败，请稍后重试',
  'invalid_scope_selection': '可选权限选择无效，请重新发起授权',
  'invalid_or_expired_challenge': '授权请求无效或已过期，请重新发起登录',
  'unmet authentication requirements': '当前账户尚未配置本次授权所需的额外验证方式',
  'invalid or expired authorization request': '授权请求无效或已过期，请重新发起登录',
  'invalid_or_expired_user_code': '设备代码无效或已过期，请核对后重试',
  'too_many_device_verification_attempts': '设备代码尝试过于频繁，请稍后重试',
  'device_authorization_unavailable': '设备授权暂时不可用，请稍后重试',
  'client_access_denied': '当前账户无权使用此应用',
  'service capability is paused': '该操作因服务维护而暂时停用',
  'service control revision conflict': '运行状态已被其他管理员修改，请重新加载后再试',
  'registration settings conflict with service control': '当前运行控制状态不允许启用该注册策略，请先调整注册或邮件投递能力',
  'service control dependency violation': '所选能力组合不满足运行控制依赖，请检查注册、认证签发与邮件投递状态',
  'invalid service control settings': '运行控制设置无效，请检查能力、原因和恢复时间',
  'service control is temporarily unavailable': '运行控制暂时不可用，请稍后重试',
  'too many service control operations': '运行控制操作过于频繁，请稍后重试',
  'settings revision conflict': '设置已被其他管理员修改，请加载最新设置后重试',
  'announcement revision conflict': '公告已被其他管理员修改，请重新加载后再试',
  'announcement state does not allow this operation': '公告状态已发生变化，请重新加载后再试',
  'announcement not found': '公告不存在、尚未开始展示或您无权查看',
  'failed to create announcement': '公告草稿创建失败，请稍后重试',
  'failed to update announcement': '公告保存失败，请重新加载后重试',
  'failed to publish announcement': '公告发布失败，请稍后重试',
  'failed to archive announcement': '公告归档失败，请稍后重试',
  'failed to load announcements': '公告列表暂时无法加载，请稍后重试',
  'failed to load notifications': '站内消息暂时无法加载，请稍后重试',
  'failed to load notification count': '消息未读状态暂时无法加载',
  'invalid security settings': '登录安全策略无效，请检查可信浏览器有效期',
  'failed to list login history': '登录历史暂时无法加载，请稍后重试',
  'failed to list trusted devices': '可信浏览器暂时无法加载，请稍后重试',
  'invalid trusted device id': '可信浏览器标识无效，请刷新页面后重试',
  'trusted device not found': '该可信浏览器已被撤销或不存在',
  'failed to revoke trusted device': '暂时无法撤销可信浏览器，请稍后重试',
  'failed to revoke trusted devices': '暂时无法撤销可信浏览器，请稍后重试',
  'observability settings are temporarily unavailable': '可观测性设置暂时不可用，请稍后重试',
  'failed to store observability settings': '可观测性设置保存失败，请稍后重试',
	'invalid observability settings': '可观测性设置无效，请检查日志级别与运营告警阈值',
  'log_level must be info, warn, or error': '日志基线级别只能是 info、warn 或 error',
  'debug_until must be between 1 minute and 24h0m0s from now': '临时 Debug 的结束时间须在 1 分钟至 24 小时内',
  'export_interval must be a valid duration': 'OTLP 导出间隔格式无效',
  'timeout must be a valid duration': 'OTLP 超时时间格式无效',
  'otlp settings revision conflict': 'OTLP 设置已被其他管理员修改，请加载最新设置后重试',
  'otlp candidate changed; reload settings': 'OTLP 候选配置已发生变化，请加载最新设置后重试',
  'a recent successful otlp candidate test is required': '激活前必须先完成一次近期成功的真实 OTLP 测试',
  'the successful otlp candidate test has expired': 'OTLP 候选配置的成功测试已过期，请重新测试',
  'no previous otlp configuration is available': '没有可回滚的上一版 OTLP 配置',
  'otlp export is already disabled': 'OTLP 导出已经处于禁用状态',
  'otlp authorization cannot be inherited': '当前没有可继承的 Authorization，请输入凭据或明确清空',
  'invalid otlp configuration': 'OTLP 配置无效，请检查地址、导出间隔和超时时间',
  'otlp settings are temporarily unavailable': 'OTLP 设置暂时不可用，请稍后重试',
  'otlp configuration was activated but could not be applied on this instance': 'OTLP 配置已激活，但当前实例暂时无法应用，请检查运行状态',
  'otlp rollback was stored but could not be applied on this instance': 'OTLP 回滚已保存，但当前实例暂时无法应用，请检查运行状态',
  'otlp disable was stored but could not be applied on this instance': 'OTLP 禁用状态已保存，但当前实例暂时无法应用，请检查运行状态',
};

const API_ERROR_MESSAGES_BY_CODE: Record<string, string> = {
  'auth.invalid_credentials': 'invalid credentials',
  'auth.current_password_incorrect': 'current password is incorrect',
  'auth.authentication_required': 'authentication required',
  'auth.recent_authentication_required': 'recent authentication is required',
  'auth.password_reauthentication_unavailable': 'password reauthentication is unavailable',
  'auth.password_login_unavailable': 'password login is not available for this account',
  'auth.password_already_configured': 'a local password is already configured',
  'auth.reauthentication_failed': 'reauthentication failed',
  'auth.reauthentication_session_update_failed': 'reauthentication session could not be updated',
  'security.csrf_validation_failed': 'csrf_validation_failed',
  'account.password_change_required': 'password change required',
  'account.email_verification_required': 'email verification is required before signing in',
  'registration.closed': 'registration is closed',
  'registration.invite_required': 'invite code is required',
  'registration.invite_invalid': 'invalid or expired invite code',
  'registration.identity_conflict': 'username or email is already taken',
  'registration.email_domain_not_allowed': 'email domain is not allowed',
  'registration.rate_limited': 'too many registration attempts',
  'registration.unavailable': 'registration is temporarily unavailable',
  'registration.mail_not_configured': 'registration requires email delivery, which is not configured',
  'mail.settings_unavailable': 'mail settings are temporarily unavailable',
  'mail.configuration_invalid': 'mail configuration is invalid',
  'mail.version_not_found': 'mail configuration version was not found',
  'mail.revision_conflict': 'mail settings changed; reload and try again',
  'mail.test_required': 'a successful candidate test is required',
  'mail.test_expired': 'the successful candidate test has expired',
  'mail.rollback_unavailable': 'no previous mail configuration is available',
  'mail.already_disabled': 'mail is already disabled',
  'mail.registration_must_close': 'close self-registration before disabling mail',
  'mail.rate_limited': 'too many mail settings operations',
  'mail.template_test_recipient_unverified': 'a verified administrator email is required for template tests',
  'mail.template_test_recipient_mismatch': "test recipient must match the administrator's verified email",
  'mail.delivery_unavailable': 'mail delivery is unavailable',
  'mail.template_test_delivery_failed': 'test email could not be delivered',
  'mail.connect_timeout_invalid': 'connect_timeout must be a valid duration',
  'mail.send_timeout_invalid': 'send_timeout must be a valid duration',
  'mail.plain_forbidden': 'plain smtp is forbidden in production',
  'mail.public_base_url_insecure': 'public_base_url must use https in production',
  'account.email_invalid': 'email is invalid',
  'mfa.challenge_expired': 'mfa challenge expired',
  'mfa.challenge_unavailable': 'mfa challenge temporarily unavailable',
  'mfa.verification_unavailable': 'mfa verification temporarily unavailable',
  'mfa.rate_limited': 'too many mfa attempts',
  'mfa.code_invalid': 'invalid mfa code',
  'mfa.totp_invalid': 'invalid totp code',
  'mfa.method_unsupported': 'unsupported mfa method',
  'auth.account_changed': 'account changed; sign in again',
  'mfa.enrollment_required': 'mfa enrollment is required; contact an administrator',
  'mfa.totp_enrollment_disabled': 'totp enrollment is disabled',
  'mfa.totp_already_enrolled': 'totp is already enrolled',
  'mfa.totp_enrollment_restart_required': 'totp enrollment must be restarted',
  'mfa.totp_not_enrolled': 'totp is not enrolled',
  'mfa.required_for_admins': 'mfa is required for active administrators',
  'mfa.admin_enrollment_incomplete': 'all active administrators must enroll mfa before it can be required',
  'mfa.totp_required_by_policy': 'totp must remain enabled while administrator mfa is required',
  'passkey.login_unavailable': 'passkey login temporarily unavailable',
  'passkey.ceremony_unavailable': 'passkey ceremony temporarily unavailable',
  'passkey.verification_unavailable': 'passkey verification temporarily unavailable',
  'passkey.reauthentication_unavailable': 'passkey reauthentication temporarily unavailable',
  'passkey.registration_unavailable': 'passkey registration temporarily unavailable',
  'passkey.registered_sign_in_required': 'passkey registered; please sign in again',
  'passkey.removed_sign_in_required': 'passkey removed; please sign in again',
  'passkey.verification_failed': 'passkey verification failed',
  'passkey.registration_invalid': 'passkey registration could not be verified',
  'passkey.enrollment_disabled': 'passkey enrollment is disabled',
  'passkey.already_registered': 'this passkey is already registered',
  'passkey.none_registered': 'no passkey is registered',
  'passkey.not_found': 'passkey not found',
  'passkey.name_invalid': 'passkey name must contain 1 to 64 characters',
  'passkey.last_authenticator': 'add a password, provider identity, or another passkey before removing this passkey',
  'passkey.ceremony_id_required': 'webauthn ceremony id is required',
  'passkey.ceremony_expired': 'webauthn ceremony expired',
  'passkey.ceremony_invalid': 'webauthn ceremony is invalid',
  'passkey.rate_limited': 'too many passkey ceremonies',
  'avatar.too_large': 'avatar image exceeds 8 mib',
  'avatar.media_type_invalid': 'avatar media type must be jpeg, png, or static webp',
  'avatar.animated_webp_unsupported': 'animated webp avatars are not supported',
  'avatar.dimensions_invalid': 'avatar image dimensions are invalid',
  'avatar.square_required': 'user avatar upload must be square after browser crop',
  'avatar.rate_limited': 'too many avatar operations',
  'avatar.operation_unavailable': 'avatar operation is temporarily unavailable',
  'avatar.storage_unavailable': 'avatar storage is temporarily unavailable',
  'media.operation_unavailable': 'media operation is temporarily unavailable',
  'media.processing_unavailable': 'media processing is temporarily unavailable',
  'media.operation_rate_limited': 'too many media operations',
  'media.settings_unavailable': 'media settings are temporarily unavailable',
  'media.configuration_invalid': 'media storage configuration is invalid',
  'media.revision_conflict': 'media settings changed; reload and try again',
  'media.candidate_not_found': 'media storage candidate was not found',
  'media.test_required': 'a recent successful media storage test is required',
  'media.migration_active': 'a media storage migration is already active',
  'media.migration_not_found': 'media storage migration was not found',
  'media.migration_not_paused': 'media writes must be paused before migration',
  'media.instances_not_ready': 'active instances are still preparing the media storage candidate',
  'media.draining': 'media writes are still draining; retry after service control is applied',
  'media.maintenance_expiry': 'clear the current maintenance expiry before starting media migration',
  'media.rate_limited': 'too many media settings operations',
  'service.capability_paused': 'service capability is paused',
  'service_control.revision_conflict': 'service control revision conflict',
  'service_control.registration_conflict': 'registration settings conflict with service control',
  'service_control.dependency_violation': 'service control dependency violation',
  'service_control.invalid_settings': 'invalid service control settings',
  'service_control.unavailable': 'service control is temporarily unavailable',
  'service_control.rate_limited': 'too many service control operations',
  'settings.revision_conflict': 'settings revision conflict',
	'announcement.revision_conflict': 'announcement revision conflict',
	'announcement.invalid_transition': 'announcement state does not allow this operation',
	'announcement.not_found': 'announcement not found',
  'settings.configuration_invalid': 'invalid security settings',
  'login_history.unavailable': 'failed to list login history',
  'trusted_device.list_unavailable': 'failed to list trusted devices',
  'trusted_device.id_invalid': 'invalid trusted device id',
  'trusted_device.not_found': 'trusted device not found',
  'trusted_device.revoke_unavailable': 'failed to revoke trusted device',
  'observability.settings_unavailable': 'observability settings are temporarily unavailable',
  'observability.store_failed': 'failed to store observability settings',
  'observability.log_level_invalid': 'log_level must be info, warn, or error',
  'observability.debug_until_invalid': 'debug_until must be between 1 minute and 24h0m0s from now',
	'observability.configuration_invalid': 'invalid observability settings',
  'telemetry.revision_conflict': 'otlp settings revision conflict',
  'telemetry.candidate_changed': 'otlp candidate changed; reload settings',
  'telemetry.test_required': 'a recent successful otlp candidate test is required',
  'telemetry.test_expired': 'the successful otlp candidate test has expired',
  'telemetry.rollback_unavailable': 'no previous otlp configuration is available',
  'telemetry.already_disabled': 'otlp export is already disabled',
  'telemetry.authorization_inheritance': 'otlp authorization cannot be inherited',
  'telemetry.configuration_invalid': 'invalid otlp configuration',
  'telemetry.settings_unavailable': 'otlp settings are temporarily unavailable',
	'telemetry.export_interval_invalid': 'export_interval must be a valid duration',
	'telemetry.timeout_invalid': 'timeout must be a valid duration',
	'telemetry.activation_apply_failed': 'otlp configuration was activated but could not be applied on this instance',
	'telemetry.rollback_apply_failed': 'otlp rollback was stored but could not be applied on this instance',
	'telemetry.disable_apply_failed': 'otlp disable was stored but could not be applied on this instance',
  'client.quota_exceeded': 'application limit reached',
  'client.self_service_disabled': 'self-service client creation is disabled',
  'client.policy_changed': 'oauth client policy changed; reload and retry',
  'client.configuration_invalid': 'invalid oauth client',
  'client.publisher_verification_not_applicable': 'publisher verification is not applicable to system-managed clients',
  'client.publisher_verification_unchanged': 'publisher verification status is unchanged',
  'oauth.unmet_authentication_requirements': 'unmet authentication requirements',
  'oauth.authorization_request_invalid': 'invalid or expired authorization request',
};

export function localizeAPIErrorMessage(message: string, code = ''): string {
  const normalized = message.trim().toLowerCase();
  if (code === 'client.configuration_invalid' || normalized.startsWith('invalid oauth client:')) {
    const disabledScope = message.match(/scope "([^"]+)" is disabled by OAuth policy/i);
    if (disabledScope) return `Scope “${disabledScope[1]}” 已被管理员停用，请重新打开窗口后选择当前可用权限`;
    const administratorScope = message.match(/scope "([^"]+)" requires administrator assignment/i);
    if (administratorScope) return `Scope “${administratorScope[1]}” 只能由管理员分配`;
    const disabledGrant = message.match(/grant "([^"]+)" is disabled by OAuth policy/i);
    if (disabledGrant) return `Grant “${disabledGrant[1]}” 已被管理员停用，请重新打开窗口后选择当前可用类型`;
    const unavailableClaim = message.match(/claim "([^"]+)" is not assignable for the selected scopes/i);
    if (unavailableClaim) return `Claim “${unavailableClaim[1]}” 已不再适用于当前 Scope，请重新打开窗口检查权限`;
    if (normalized.includes('public client creation is disabled by oauth policy')) return '管理员已停用 Public Client 创建，请重新打开窗口检查配置';
    return '应用配置不符合当前 OAuth 策略，请重新打开窗口检查后重试';
  }
  const stableMessage = API_ERROR_MESSAGES_BY_CODE[code];
  if (stableMessage && API_ERROR_TRANSLATIONS[stableMessage]) return API_ERROR_TRANSLATIONS[stableMessage];
  if (code === 'auth.password_policy_violation') return PASSWORD_REQUIREMENT;
  if (normalized.includes(PASSWORD_POLICY_ERROR)) return PASSWORD_REQUIREMENT;
  if (API_ERROR_TRANSLATIONS[normalized]) return API_ERROR_TRANSLATIONS[normalized];
  if (normalized.startsWith('invalid otlp configuration:')) return API_ERROR_TRANSLATIONS['invalid otlp configuration'];
  if (/^(mail_backlog_count|audit_outbox_backlog_count|avatar_cleanup_pending_count) must be between /.test(normalized)) {
    return '运营告警数量阈值须为 1 至 1,000,000 的整数';
  }
  if (/^(mail_oldest_pending_age|audit_oldest_pending_age) must be a duration between /.test(normalized)) {
    return '运营告警时长阈值须在 1 分钟至 7 天之间';
  }
  if (code === 'request_failed' && /^[\x00-\x7F]*$/.test(message)) return '请求失败，请稍后重试';
  return message;
}

export function isAPIErrorCode(cause: unknown, code: string): cause is ApiError {
  return cause instanceof ApiError && cause.code === code;
}

export function isRecentAuthenticationError(cause: unknown): cause is ApiError {
  return cause instanceof ApiError
    && cause.status === 403
    && cause.code === 'auth.recent_authentication_required';
}

let csrfToken = '';

export function setCsrfToken(value: string | null | undefined): void {
  csrfToken = value || '';
}

function isMutation(method?: string): boolean {
  return !['GET', 'HEAD', 'OPTIONS'].includes((method || 'GET').toUpperCase());
}

function currentRelativeURL(): string {
  if (typeof window === 'undefined') return '/';
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

async function req<T>(path: string, opts: RequestInit = {}, redirectOnUnauthorized = true): Promise<T> {
  const requestHeaders = new Headers(opts.headers);
  if (opts.body && !(opts.body instanceof FormData) && !requestHeaders.has('Content-Type')) {
    requestHeaders.set('Content-Type', 'application/json');
  }
  if (path.startsWith('/api/') && isMutation(opts.method) && csrfToken && !requestHeaders.has('X-CSRF-Token')) {
    requestHeaders.set('X-CSRF-Token', csrfToken);
  }

  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    credentials: 'same-origin',
    headers: requestHeaders,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({})) as APIErrorResponse;
    if (res.status === 401 && redirectOnUnauthorized) {
      setCsrfToken('');
      if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
        window.location.assign(`/login?return_to=${encodeURIComponent(currentRelativeURL())}`);
      }
    }
    const retryAfterHeader = res.headers.get('Retry-After');
    const retryAfter = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : undefined;
    const message = body.error_description || body.message || body.error || `请求失败 (${res.status})`;
    throw new ApiError(
      localizeAPIErrorMessage(message, body.code),
      res.status,
      Number.isFinite(retryAfter) ? retryAfter : undefined,
      message,
      body,
      body.code,
    );
  }

  if (res.status === 204) return undefined as T;
  const responseBody = await res.text();
  if (!responseBody) return undefined as T;
  let data: T;
  try {
    data = JSON.parse(responseBody) as T;
  } catch {
    throw new ApiError('服务返回了无法解析的响应', res.status);
  }
  const maybeSession = data as Partial<SessionInfo> & { status?: unknown };
  if (maybeSession.csrf_token && maybeSession.status !== 'mfa_required') {
    setCsrfToken(maybeSession.csrf_token);
  }
  return data;
}

function normalizedStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

export function normalizeOAuthClient<T extends OAuthClient>(client: T): T {
  return {
    ...client,
    homepage_uri: client.homepage_uri || '',
    privacy_policy_uri: client.privacy_policy_uri || '',
    terms_of_service_uri: client.terms_of_service_uri || '',
    identity_revision: Number.isSafeInteger(client.identity_revision) ? client.identity_revision : 1,
    authorization_revision: Number.isSafeInteger(client.authorization_revision) ? client.authorization_revision : 1,
    redirect_uris: normalizedStringArray(client.redirect_uris),
    post_logout_redirect_uris: normalizedStringArray(client.post_logout_redirect_uris),
    grants: normalizedStringArray(client.grants),
    scopes: normalizedStringArray(client.scopes),
    optional_scopes: normalizedStringArray(client.optional_scopes),
    allowed_claims: normalizedStringArray(client.allowed_claims),
    authorization_count: Number.isFinite(client.authorization_count) ? Number(client.authorization_count) : 0,
    success_count_7d: Number.isFinite(client.success_count_7d) ? Number(client.success_count_7d) : 0,
    failure_count_7d: Number.isFinite(client.failure_count_7d) ? Number(client.failure_count_7d) : 0,
  };
}

export function normalizeOAuthAuthorization(authorization: OAuthAuthorization): OAuthAuthorization {
  return {
    ...authorization,
    client_name_at_grant: authorization.client_name_at_grant || authorization.client_name,
    homepage_uri: authorization.homepage_uri || '',
    privacy_policy_uri: authorization.privacy_policy_uri || '',
    terms_of_service_uri: authorization.terms_of_service_uri || '',
    homepage_uri_at_grant: authorization.homepage_uri_at_grant || '',
    privacy_policy_uri_at_grant: authorization.privacy_policy_uri_at_grant || '',
    terms_of_service_uri_at_grant: authorization.terms_of_service_uri_at_grant || '',
    client_identity_revision: Number.isSafeInteger(authorization.client_identity_revision) ? authorization.client_identity_revision : 1,
    current_identity_revision: Number.isSafeInteger(authorization.current_identity_revision) ? authorization.current_identity_revision : 1,
    client_authorization_revision: Number.isSafeInteger(authorization.client_authorization_revision) ? authorization.client_authorization_revision : 1,
    current_authorization_revision: Number.isSafeInteger(authorization.current_authorization_revision) ? authorization.current_authorization_revision : 1,
    application_changed: authorization.application_changed === true,
    reauthorization_required: authorization.reauthorization_required === true,
    scopes: normalizedStringArray(authorization.scopes),
    allowed_claims: normalizedStringArray(authorization.allowed_claims),
  };
}

export function normalizeConsentRequest(consent: ConsentRequest): ConsentRequest {
  return {
    ...consent,
    flow: consent.flow === 'device_authorization' ? 'device_authorization' : 'authorization_code',
    scopes: normalizedStringArray(consent.scopes),
    permissions: Array.isArray(consent.permissions) ? consent.permissions.map((permission) => ({
      ...permission,
      claims: normalizedStringArray(permission.claims),
      previously_granted: permission.previously_granted === true,
      newly_requested: permission.newly_requested === true,
    })) : [],
    new_scopes: normalizedStringArray(consent.new_scopes),
    new_claims: normalizedStringArray(consent.new_claims),
    previously_authorized: consent.previously_authorized === true,
    application_changed: consent.application_changed === true,
    reauthorization_required: consent.reauthorization_required === true,
    step_up_required: consent.step_up_required === true,
    required_acr: typeof consent.required_acr === 'string' ? consent.required_acr : '',
    max_age: Number.isSafeInteger(consent.max_age) && Number(consent.max_age) >= 0 ? Number(consent.max_age) : null,
  };
}

export function normalizeSecuritySettings(settings: SecuritySettings): SecuritySettings {
  return {
    ...settings,
    trusted_devices_enabled: settings.trusted_devices_enabled !== false,
    trusted_device_ttl: settings.trusted_device_ttl || '720h0m0s',
  };
}

export const api = {
  login: (username: string, password: string, returnTo: string, humanVerification?: HumanVerificationProof) =>
    req<LoginResponse>('/api/login', {
      method: 'POST', body: JSON.stringify({ username, password, return_to: returnTo, human_verification: humanVerification }),
    }, false),
  getLoginMFA: () => req<MFARequiredResponse>('/api/login/mfa', { cache: 'no-store' }, false),
  verifyLoginMFA: (method: CodeMFAMethod, code: string, pendingCsrf: string, trustDevice = false) => req<SessionInfo>('/api/login/mfa', {
    method: 'POST',
    headers: { 'X-CSRF-Token': pendingCsrf },
    body: JSON.stringify({ method, code, trust_device: trustDevice }),
  }, false),
  cancelLoginMFA: (pendingCsrf: string) => req<void>('/api/login/mfa', {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': pendingCsrf },
  }, false),
  session: () => req<SessionInfo>('/api/session', { cache: 'no-store' }, false),
  logout: () => req<void>('/api/logout', { method: 'POST' }),
  getMe: () => req<User>('/api/me'),
  updateMe: (data: Pick<UpdateUserInput, 'display_name'>) =>
    req<User>('/api/me', { method: 'PUT', body: JSON.stringify(data) }),
  uploadAvatar: (blob: Blob) => {
    const body = new FormData();
    body.append('avatar', blob, blob.type === 'image/png' ? 'avatar.png' : 'avatar.webp');
    return req<User>('/api/me/avatar', { method: 'POST', body });
  },
  removeAvatar: () => req<User>('/api/me/avatar', { method: 'DELETE' }),
  changePassword: (currentPassword: string, newPassword: string) =>
    req<SessionInfo>('/api/me/password', {
      method: 'POST',
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }, false),
  getBranding: () => req<Branding>('/api/branding', {}, false),
  getServiceStatus: () => req<ServiceStatus>('/api/service-status', { cache: 'no-store' }, false),
  getSiteBanner: () => req<PublicSiteBannerResponse>('/api/site-banner', { cache: 'no-store' }, false),
  getMessages: (filters: MessageCenterFilters = {}) => {
    const params = new URLSearchParams({
      page: String(filters.page || 1),
      page_size: String(filters.pageSize || 20),
      kind: filters.kind || 'all',
      read: filters.read || 'all',
    });
    if (filters.severity) params.set('severity', filters.severity);
    if (filters.query) params.set('q', filters.query);
    if (filters.from) params.set('from', filters.from);
    if (filters.to) params.set('to', filters.to);
    return req<PaginatedResponse<MessageCenterItem>>(`/api/messages?${params}`, { cache: 'no-store' });
  },
  markAllMessagesRead: (kind: MessageCenterKind = 'all') => req<void>(`/api/messages/read-all?kind=${encodeURIComponent(kind)}`, { method: 'POST' }),
  getAnnouncements: (page = 1, pageSize = 20) => req<PaginatedResponse<Announcement>>(`/api/announcements?page=${page}&page_size=${pageSize}`, { cache: 'no-store' }),
  getAnnouncement: (id: string) => req<Announcement>(`/api/announcements/${encodeURIComponent(id)}`, { cache: 'no-store' }),
  markAnnouncementRead: (id: string) => req<void>(`/api/announcements/${encodeURIComponent(id)}/read`, { method: 'POST' }),
  getNotifications: (page = 1, pageSize = 20, unread = false) => req<PaginatedResponse<UserNotification>>(`/api/notifications?page=${page}&page_size=${pageSize}&unread=${unread}`, { cache: 'no-store' }),
  getNotificationUnreadCount: () => req<NotificationUnreadCount>('/api/notifications/unread-count', { cache: 'no-store' }),
  markNotificationRead: (id: string) => req<void>(`/api/notifications/${encodeURIComponent(id)}/read`, { method: 'POST' }),
  markAllNotificationsRead: () => req<void>('/api/notifications/read-all', { method: 'POST' }),
  getRegistrationOptions: () => req<RegistrationOptions>('/api/registration', {}, false),
  getHumanVerification: (action: HumanVerificationAction) =>
    req<HumanVerificationChallenge>(`/api/human-verification?action=${encodeURIComponent(action)}`, { cache: 'no-store' }, false),
  register: (data: RegisterInput) =>
    req<RegisterResult>('/api/register', { method: 'POST', body: JSON.stringify(data) }, false),
  resendPendingEmailVerification: (email: string, humanVerification?: HumanVerificationProof) =>
    req<{ status: 'accepted' }>('/api/email/verification/resend', {
      method: 'POST', body: JSON.stringify({ email, human_verification: humanVerification }),
    }, false),
  startProviderLogin: (provider: string, returnTo: string, humanVerification?: HumanVerificationProof) =>
    req<{ redirect_url: string }>(`/api/provider-login/${encodeURIComponent(provider)}`, {
      method: 'POST', body: JSON.stringify({ return_to: returnTo, human_verification: humanVerification }),
    }, false),
  getProviders: () => req<ProviderSummary[]>('/api/providers'),
  getMyIdentities: () => req<ExternalIdentity[]>('/api/me/identities'),
  bindIdentity: (provider: string, returnTo = '/profile') =>
    req<{ redirect_url: string }>(`/api/me/identities/${encodeURIComponent(provider)}/bind`, {
      method: 'POST',
      body: JSON.stringify({ return_to: returnTo }),
    }),
  getMySessions: () => req<BrowserSession[]>('/api/me/sessions'),
  revokeMySession: (id: string) => req<void>(`/api/me/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  revokeOtherSessions: () => req<{ revoked: number }>('/api/me/sessions/revoke-others', { method: 'POST' }),
  getMyTrustedDevices: () => req<TrustedDevicesResponse>('/api/me/trusted-devices', { cache: 'no-store' }),
  revokeMyTrustedDevice: (id: string) => req<void>(`/api/me/trusted-devices/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  revokeOtherTrustedDevices: () => req<{ revoked: number }>('/api/me/trusted-devices/revoke-others', { method: 'POST' }),
  getMyLoginHistory: (page = 1, pageSize = 20) =>
    req<PaginatedResponse<LoginHistoryEntry>>(`/api/me/login-history?page=${page}&page_size=${pageSize}`, { cache: 'no-store' }),
  reauthenticateWithPassword: (password: string) => req<ReauthenticationResponse>('/api/me/reauth/password', {
    method: 'POST',
    body: JSON.stringify({ password }),
  }, false),
  reauthenticateWithProvider: (provider: string, returnTo = '/profile') => req<{ redirect_url: string }>(`/api/me/reauth/${encodeURIComponent(provider)}`, {
    method: 'POST',
    body: JSON.stringify({ return_to: returnTo }),
  }),
  beginPasskeyLogin: (conditional: boolean, returnTo: string, signal?: AbortSignal) => req<PasskeyAuthenticationOptions>('/api/login/passkey/options', {
    method: 'POST',
    body: JSON.stringify({ conditional, return_to: returnTo }),
    signal,
  }, false),
  finishPasskeyLogin: (ceremonyID: string, credential: unknown, signal?: AbortSignal) => req<SessionInfo>('/api/login/passkey/verify', {
    method: 'POST',
    headers: { 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  beginMFAPasskey: (pendingCsrf: string, signal?: AbortSignal) => req<PasskeyAuthenticationOptions>('/api/login/mfa/passkey/options', {
    method: 'POST',
    headers: { 'X-CSRF-Token': pendingCsrf },
    signal,
  }, false),
  finishMFAPasskey: (ceremonyID: string, credential: unknown, pendingCsrf: string, signal?: AbortSignal, trustDevice = false) => req<SessionInfo>('/api/login/mfa/passkey/verify', {
    method: 'POST',
    headers: {
      'X-CSRF-Token': pendingCsrf,
      'X-WebAuthn-Ceremony': ceremonyID,
      ...(trustDevice ? { 'X-Trust-Device': 'true' } : {}),
    },
    body: JSON.stringify(credential),
    signal,
  }, false),
  beginPasskeyReauthentication: (signal?: AbortSignal) => req<PasskeyAuthenticationOptions>('/api/me/reauth/passkey/options', { method: 'POST', signal }, false),
  finishPasskeyReauthentication: (ceremonyID: string, credential: unknown, signal?: AbortSignal) => req<SessionInfo>('/api/me/reauth/passkey/verify', {
    method: 'POST',
    headers: { 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  getMyMFA: () => req<MFAStatus>('/api/me/mfa', { cache: 'no-store' }),
  beginTOTPEnrollment: () => req<TOTPEnrollment>('/api/me/mfa/totp/enroll', { method: 'POST' }),
  confirmTOTPEnrollment: (code: string) => req<TOTPConfirmationResult>('/api/me/mfa/totp/enroll/confirm', {
    method: 'POST', body: JSON.stringify({ code }),
  }),
  regenerateRecoveryCodes: () => req<RecoveryCodesResult>('/api/me/mfa/recovery-codes', { method: 'POST' }),
  disableTOTP: () => req<SessionInfo>('/api/me/mfa/totp', { method: 'DELETE' }),
  getMyPasskeys: () => req<{ passkeys: PasskeyCredential[] }>('/api/me/passkeys', { cache: 'no-store' }),
  beginPasskeyRegistration: (name: string, signal?: AbortSignal) => req<PasskeyRegistrationOptions>('/api/me/passkeys/registration/options', {
    method: 'POST',
    body: JSON.stringify({ name }),
    signal,
  }),
  finishPasskeyRegistration: (ceremonyID: string, credential: unknown, signal?: AbortSignal) => req<PasskeyRegistrationResult>('/api/me/passkeys/registration/verify', {
    method: 'POST',
    headers: { 'X-WebAuthn-Ceremony': ceremonyID },
    body: JSON.stringify(credential),
    signal,
  }, false),
  renamePasskey: (id: string, name: string) => req<PasskeyCredential>(`/api/me/passkeys/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify({ name }),
  }),
  deletePasskey: (id: string) => req<SessionInfo>(`/api/me/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' }, false),
  setPassword: (newPassword: string) => req<SessionInfo>('/api/me/password/set', {
    method: 'POST',
    body: JSON.stringify({ new_password: newPassword }),
  }),
  deleteMyIdentity: (identityID: string) => req<SessionInfo>(`/api/me/identities/${encodeURIComponent(identityID)}`, { method: 'DELETE' }),
  getMyAuthorizations: async (filters: { q?: string; status?: string; page?: number; pageSize?: number } = {}) => {
    const params = new URLSearchParams({ page: String(filters.page || 1), page_size: String(filters.pageSize || 20) });
    if (filters.q) params.set('q', filters.q);
    if (filters.status) params.set('status', filters.status);
    const result = await req<PaginatedResponse<OAuthAuthorization>>(`/api/me/authorizations?${params}`);
    return { ...result, items: (Array.isArray(result.items) ? result.items : []).map(normalizeOAuthAuthorization) };
  },
  revokeMyAuthorization: (clientID: string) => req<void>(`/api/me/authorizations/${encodeURIComponent(clientID)}`, { method: 'DELETE' }),
  discovery: () => req<OIDCDiscoveryDocument>('/.well-known/openid-configuration', {}, false),

  account: {
    requestPasswordReset: (email: string, humanVerification?: HumanVerificationProof) => req<void>('/api/password/forgot', {
      method: 'POST',
      body: JSON.stringify({ email, human_verification: humanVerification }),
    }, false),
    confirmPasswordReset: (token: string, newPassword: string) => req<void>('/api/password/reset', {
      method: 'POST',
      body: JSON.stringify({ token, new_password: newPassword }),
    }, false),
    requestEmailVerification: () => req<void>('/api/me/email/verification', { method: 'POST' }),
    confirmEmailVerification: (token: string) => req<void>('/api/email/verify', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }, false),
    requestEmailChange: (email: string) => req<void>('/api/me/email/change', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),
    confirmEmailChange: (token: string) => req<void>('/api/email/change/confirm', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }, false),
  },

  consent: {
    get: async (challenge: string) => normalizeConsentRequest(await req<ConsentRequest>(`/api/consent?challenge=${encodeURIComponent(challenge)}`)),
    stepUp: (challenge: string) => req<ConsentStepUpResponse>('/api/consent/step-up', { method: 'POST', body: JSON.stringify({ challenge }) }),
    accept: (challenge: string, grantedOptionalScopes: string[]) => req<{ redirect_url: string }>('/api/consent/accept', { method: 'POST', body: JSON.stringify({ challenge, granted_optional_scopes: grantedOptionalScopes }) }),
    deny: (challenge: string) => req<{ redirect_url: string }>('/api/consent/deny', { method: 'POST', body: JSON.stringify({ challenge }) }),
  },

  deviceAuthorization: {
    prepare: (userCode: string) => req<{ consent_url: string }>('/api/device-authorization/prepare', {
      method: 'POST', body: JSON.stringify({ user_code: userCode }),
    }),
  },

  my: {
    getClients: async () => {
      const result = await req<MyClientPage>('/api/my/clients', { cache: 'no-store' });
      return { ...result, items: (Array.isArray(result.items) ? result.items : []).map(normalizeOAuthClient) };
    },
    getClient: async (id: string) => normalizeOAuthClient(await req<OAuthClient>(`/api/my/clients/${encodeURIComponent(id)}`, { cache: 'no-store' })),
    getClientInsights: (id: string, days = 30) => req<OAuthClientInsights>(`/api/my/clients/${encodeURIComponent(id)}/insights?days=${days}`, { cache: 'no-store' }),
    getClientDiagnostics: (id: string, filters: OAuthDiagnosticFilters = {}) => {
      const params = new URLSearchParams({ page: String(filters.page || 1), page_size: String(filters.pageSize || 20) });
      if (filters.flow) params.set('flow', filters.flow);
      if (filters.stage) params.set('stage', filters.stage);
      if (filters.reason) params.set('reason', filters.reason);
      return req<PaginatedResponse<OAuthClientDiagnostic>>(`/api/my/clients/${encodeURIComponent(id)}/diagnostics?${params}`, { cache: 'no-store' });
    },
    createClient: async (data: CreateClientInput) => normalizeOAuthClient(await req<CreateClientResult>('/api/my/clients', { method: 'POST', body: JSON.stringify(data) })),
    updateClient: async (id: string, data: UpdateClientInput) => normalizeOAuthClient(await req<OAuthClient>(`/api/my/clients/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(data) })),
    uploadClientLogo: async (id: string, blob: Blob) => {
      const body = new FormData();
      body.append('logo', blob, blob.type === 'image/png' ? 'logo.png' : 'logo.webp');
      return normalizeOAuthClient(await req<OAuthClient>(`/api/my/clients/${encodeURIComponent(id)}/logo`, { method: 'POST', body }));
    },
    removeClientLogo: async (id: string) => normalizeOAuthClient(await req<OAuthClient>(`/api/my/clients/${encodeURIComponent(id)}/logo`, { method: 'DELETE' })),
    deleteClient: (id: string) => req<void>(`/api/my/clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    rotateClientSecret: (id: string) => req<RotateClientSecretResult>(`/api/my/clients/${encodeURIComponent(id)}/rotate-secret`, { method: 'POST' }),
  },

  admin: {
    getStats: () => req<DashboardStats>('/api/admin/stats'),
    getLoginTrend: (days = 7) => req<LoginTrend>(`/api/admin/stats/login-trend?days=${days}`),
    getRegistrationTrend: (days: StatsTrendDays = 30) =>
      req<RegistrationTrend>(`/api/admin/stats/registration-trend?days=${days}`),
    getMailTrend: (days: StatsTrendDays = 30) =>
      req<MailTrend>(`/api/admin/stats/mail-trend?days=${days}`),
    getRecentLogins: (limit = 5) => req<RecentLogin[]>(`/api/admin/stats/recent-logins?limit=${limit}`),
    getSystemStatus: () => req<SystemStatus>('/api/admin/system/status'),
    getHumanVerificationSettings: () => req<HumanVerificationSettings>('/api/admin/settings/human-verification', { cache: 'no-store' }),
    saveHumanVerificationCandidate: (input: SaveHumanVerificationCandidateInput) =>
      req<HumanVerificationCandidateResult>('/api/admin/settings/human-verification/candidate', { method: 'PUT', body: JSON.stringify(input) }),
    testHumanVerificationCandidate: (expectedRevision: number, versionID: string, proof: HumanVerificationProof) =>
      req<HumanVerificationTestResult>('/api/admin/settings/human-verification/candidate/test', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID, ...proof }),
      }),
    activateHumanVerification: (expectedRevision: number, versionID: string, policy: HumanVerificationPolicy) =>
      req<HumanVerificationState>('/api/admin/settings/human-verification/activate', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID, policy }),
      }),
    updateHumanVerificationPolicy: (expectedRevision: number, policy: HumanVerificationPolicy) =>
      req<HumanVerificationState>('/api/admin/settings/human-verification/policy', {
        method: 'PUT', body: JSON.stringify({ expected_revision: expectedRevision, policy }),
      }),
    rollbackHumanVerification: (expectedRevision: number) =>
      req<HumanVerificationState>('/api/admin/settings/human-verification/rollback', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    disableHumanVerification: (expectedRevision: number) =>
      req<HumanVerificationState>('/api/admin/settings/human-verification/disable', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    enableHumanVerification: (expectedRevision: number) =>
      req<HumanVerificationState>('/api/admin/settings/human-verification/enable', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    getOperationsSettings: () => req<OperationsSettings>('/api/admin/settings/operations', { cache: 'no-store' }),
    updateOperationsSettings: (settings: UpdateOperationsSettingsInput) =>
      req<OperationsSettings>('/api/admin/settings/operations', { method: 'PUT', body: JSON.stringify(settings) }),
    getProtectionSettings: () => req<ProtectionSettings>('/api/admin/settings/protection', { cache: 'no-store' }),
    updateProtectionSettings: (settings: UpdateProtectionSettingsInput) =>
      req<ProtectionSettings>('/api/admin/settings/protection', { method: 'PUT', body: JSON.stringify(settings) }),
    getLifecycleSettings: () => req<LifecycleSettings>('/api/admin/settings/lifecycle', { cache: 'no-store' }),
    updateLifecycleSettings: (settings: UpdateLifecycleSettingsInput) =>
      req<LifecycleSettings>('/api/admin/settings/lifecycle', { method: 'PUT', body: JSON.stringify(settings) }),
    getOAuthSettings: () => req<OAuthSettings>('/api/admin/settings/oauth', { cache: 'no-store' }),
    updateOAuthSettings: (settings: UpdateOAuthSettingsInput) =>
      req<OAuthSettings>('/api/admin/settings/oauth', { method: 'PUT', body: JSON.stringify(settings) }),
    getCommunicationsSettings: () => req<CommunicationsSettings>('/api/admin/settings/communications', { cache: 'no-store' }),
    getAnnouncements: (filters: { page?: number; pageSize?: number; q?: string; status?: string; audience?: string; severity?: string } = {}) => {
      const params = new URLSearchParams({ page: String(filters.page || 1), page_size: String(filters.pageSize || 20) });
      if (filters.q) params.set('q', filters.q);
      if (filters.status) params.set('status', filters.status);
      if (filters.audience) params.set('audience', filters.audience);
      if (filters.severity) params.set('severity', filters.severity);
      return req<PaginatedResponse<Announcement>>(`/api/admin/announcements?${params}`, { cache: 'no-store' });
    },
    getAnnouncement: (id: string) => req<Announcement>(`/api/admin/announcements/${encodeURIComponent(id)}`, { cache: 'no-store' }),
    createAnnouncement: (input: AnnouncementInput) => req<Announcement>('/api/admin/announcements', { method: 'POST', body: JSON.stringify(input) }),
    updateAnnouncement: (id: string, expectedRevision: number, input: AnnouncementInput) => req<Announcement>(`/api/admin/announcements/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ expected_revision: expectedRevision, ...input }) }),
    publishAnnouncement: (id: string, expectedRevision: number) => req<Announcement>(`/api/admin/announcements/${encodeURIComponent(id)}/publish`, { method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }) }),
    archiveAnnouncement: (id: string, expectedRevision: number) => req<Announcement>(`/api/admin/announcements/${encodeURIComponent(id)}/archive`, { method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }) }),
    previewAnnouncement: (bodyMarkdown: string) => req<{ body_html: string }>('/api/admin/announcements/preview', { method: 'POST', body: JSON.stringify({ body_markdown: bodyMarkdown }) }),
    updateCommunicationsSettings: (settings: UpdateCommunicationsSettingsInput) =>
      req<CommunicationsSettings>('/api/admin/settings/communications', { method: 'PUT', body: JSON.stringify(settings) }),
    getObservabilitySettings: () =>
      req<ObservabilitySettings>('/api/admin/settings/observability', { cache: 'no-store' }),
    updateObservabilitySettings: (settings: UpdateObservabilitySettingsInput) =>
      req<ObservabilitySettings>('/api/admin/settings/observability', { method: 'PUT', body: JSON.stringify(settings) }),
    saveOTLPCandidate: (settings: SaveOTLPCandidateInput) =>
      req<SaveOTLPCandidateResult>('/api/admin/settings/observability/otlp/candidate', { method: 'PUT', body: JSON.stringify(settings) }),
    testOTLPCandidate: (expectedRevision: number, versionID: string) =>
      req<TestOTLPCandidateResult>('/api/admin/settings/observability/otlp/candidate/test', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID }),
      }),
    activateOTLPCandidate: (expectedRevision: number, versionID: string) =>
      req<OTLPMutationResult>('/api/admin/settings/observability/otlp/activate', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID }),
      }),
    rollbackOTLP: (expectedRevision: number) =>
      req<OTLPMutationResult>('/api/admin/settings/observability/otlp/rollback', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    disableOTLP: (expectedRevision: number) =>
      req<OTLPMutationResult>('/api/admin/settings/observability/otlp/disable', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    previewSiteBannerMarkdown: (message: string) =>
      req<SiteBannerMarkdownPreview>('/api/admin/settings/communications/site-banner/preview', {
        method: 'POST', body: JSON.stringify({ message }),
      }),
    previewEmailTemplate: (templateID: string, email: EmailTemplateSettings) =>
      req<EmailTemplatePreview>('/api/admin/settings/communications/email/preview', {
        method: 'POST', body: JSON.stringify({ template_id: templateID, email }),
      }),
    testEmailTemplate: (templateID: string, recipient: string, email: EmailTemplateSettings) =>
      req<{ status: 'sent' }>('/api/admin/settings/communications/email/test', {
        method: 'POST', body: JSON.stringify({ template_id: templateID, recipient, email }),
      }),
    getBrandingSettings: () => req<BrandingSettings>('/api/admin/settings/branding', { cache: 'no-store' }),
    updateBranding: (branding: UpdateBrandingSettingsInput) =>
      req<BrandingSettings>('/api/admin/settings/branding', { method: 'PUT', body: JSON.stringify(branding) }),
    getRegistrationSettings: () => req<RegistrationSettings>('/api/admin/settings/registration', { cache: 'no-store' }),
    updateRegistrationSettings: (settings: UpdateRegistrationSettingsInput) =>
      req<RegistrationSettings>('/api/admin/settings/registration', { method: 'PUT', body: JSON.stringify(settings) }),
    getSecuritySettings: () => req<SecuritySettings>('/api/admin/settings/security', { cache: 'no-store' }).then(normalizeSecuritySettings),
    updateSecuritySettings: (settings: UpdateSecuritySettingsInput) =>
      req<SecuritySettings>('/api/admin/settings/security', { method: 'PUT', body: JSON.stringify(settings) }).then(normalizeSecuritySettings),
    getMailSettings: () => req<MailSettings>('/api/admin/settings/mail'),
    saveMailCandidate: (settings: SaveMailCandidateInput) =>
      req<SaveMailCandidateResult>('/api/admin/settings/mail/candidate', { method: 'PUT', body: JSON.stringify(settings) }),
    testMailCandidate: (expectedRevision: number, versionID: string, email: string) =>
      req<MailTestResult>('/api/admin/settings/mail/candidate/test', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID, email }),
      }),
    activateMailCandidate: (expectedRevision: number, versionID: string) =>
      req<MailMutationResult>('/api/admin/settings/mail/activate', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, version_id: versionID }),
      }),
    rollbackMailSettings: (expectedRevision: number) =>
      req<MailMutationResult>('/api/admin/settings/mail/rollback', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    disableMail: (expectedRevision: number) =>
      req<MailMutationResult>('/api/admin/settings/mail/disable', {
        method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }),
      }),
    getMediaSettings: () => req<MediaStorageSettings>('/api/admin/settings/media', { cache: 'no-store' }),
    saveMediaCandidate: (settings: SaveMediaStorageCandidateInput) =>
      req<{ candidate: MediaStorageProfile; revision: number }>('/api/admin/settings/media/candidate', { method: 'PUT', body: JSON.stringify(settings) }),
    testMediaCandidate: (expectedRevision: number, profileID: string) =>
      req<{ candidate: MediaStorageProfile; revision: number; result?: string }>('/api/admin/settings/media/candidate/test', { method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, profile_id: profileID }) }),
    startMediaMigration: (expectedRevision: number, profileID: string) =>
      req<{ migration: MediaStorageMigration; revision: number }>('/api/admin/settings/media/migrations', { method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision, profile_id: profileID }) }),
    migrateMediaToLocalFallback: (expectedRevision: number) =>
      req<{ migration: MediaStorageMigration; revision: number }>('/api/admin/settings/media/fallback/migrate', { method: 'POST', body: JSON.stringify({ expected_revision: expectedRevision }) }),
    retryMediaMigration: (migrationID: string) =>
      req<{ migration: MediaStorageMigration }>(`/api/admin/settings/media/migrations/${encodeURIComponent(migrationID)}/retry`, { method: 'POST' }),
    getInvites: () => req<Invite[]>('/api/admin/invites'),
    createInvite: (data: { note?: string; max_uses?: number; ttl?: string }) =>
      req<CreateInviteResult>('/api/admin/invites', { method: 'POST', body: JSON.stringify(data) }),
    revokeInvite: (id: string) =>
      req<void>(`/api/admin/invites/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    getUsers: (page = 1, pageSize = 20, search = '', status?: UserStatus) => {
      const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
      if (search) params.set('q', search);
      if (status) params.set('status', status);
      return req<PaginatedResponse<User>>(`/api/admin/users?${params}`);
    },
    createUser: (data: CreateUserInput) => req<User>('/api/admin/users', { method: 'POST', body: JSON.stringify(data) }),
    getUserOverview: (id: string) => req<AdminUserOverview>(`/api/admin/users/${encodeURIComponent(id)}/overview`),
    getUserSecurity: (id: string) => req<AdminUserSecurity>(`/api/admin/users/${encodeURIComponent(id)}/security`),
    getUserAuthorizations: (id: string) => req<AdminUserAuthorization[]>(`/api/admin/users/${encodeURIComponent(id)}/authorizations`),
    getUserClients: (id: string, page = 1, pageSize = 20) =>
      req<ClientQuotaPage<AdminUserClientSummary>>(`/api/admin/users/${encodeURIComponent(id)}/clients?page=${page}&page_size=${pageSize}`),
    updateUserClientQuota: (id: string, quotaOverride: number | null) =>
      req<ClientQuota>(`/api/admin/users/${encodeURIComponent(id)}/client-quota`, {
        method: 'PUT', body: JSON.stringify({ quota_override: quotaOverride }),
      }),
    getUserActivity: (id: string, page = 1, pageSize = 20) =>
      req<PaginatedResponse<AuditLog>>(`/api/admin/users/${encodeURIComponent(id)}/activity?page=${page}&page_size=${pageSize}`),
    updateUser: (id: string, data: UpdateUserInput) => req<User>(`/api/admin/users/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(data) }),
    uploadUserAvatar: (id: string, blob: Blob) => {
      const body = new FormData();
      body.append('avatar', blob, blob.type === 'image/png' ? 'avatar.png' : 'avatar.webp');
      return req<User>(`/api/admin/users/${encodeURIComponent(id)}/avatar`, { method: 'POST', body });
    },
    removeUserAvatar: (id: string) => req<User>(`/api/admin/users/${encodeURIComponent(id)}/avatar`, { method: 'DELETE' }),
    deleteUser: (id: string) => req<void>(`/api/admin/users/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    resetPassword: (id: string, password: string) =>
      req<void>(`/api/admin/users/${encodeURIComponent(id)}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) }),
    suspendUser: (id: string) => req<User>(`/api/admin/users/${encodeURIComponent(id)}/suspend`, { method: 'POST' }),
    activateUser: (id: string) => req<User>(`/api/admin/users/${encodeURIComponent(id)}/activate`, { method: 'POST' }),
    updateUserRole: (id: string, role: UserRole) =>
      req<User>(`/api/admin/users/${encodeURIComponent(id)}/role`, { method: 'PUT', body: JSON.stringify({ role }) }),
    getUserIdentities: (id: string) => req<ExternalIdentity[]>(`/api/admin/users/${encodeURIComponent(id)}/identities`),
    deleteUserIdentity: (userID: string, identityID: string) =>
      req<void>(`/api/admin/users/${encodeURIComponent(userID)}/identities/${encodeURIComponent(identityID)}`, { method: 'DELETE' }),
    getUserSessions: (id: string) => req<BrowserSession[]>(`/api/admin/users/${encodeURIComponent(id)}/sessions`),
    revokeUserSession: (id: string, sessionID: string) =>
      req<void>(`/api/admin/users/${encodeURIComponent(id)}/sessions/${encodeURIComponent(sessionID)}`, { method: 'DELETE' }),
    revokeUserSessions: (id: string) => req<{ revoked: number }>(`/api/admin/users/${encodeURIComponent(id)}/sessions`, { method: 'DELETE' }),
    getClients: async (page = 1, pageSize = 20, filters: OAuthClientListFilters = {}) => {
      const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
      if (filters.q) params.set('q', filters.q);
      if (filters.type) params.set('type', filters.type);
      if (filters.grant) params.set('grant', filters.grant);
      if (filters.accessPolicy) params.set('access_policy', filters.accessPolicy);
      if (filters.publisherStatus) params.set('publisher_status', filters.publisherStatus);
      if (filters.ownership) params.set('ownership', filters.ownership);
      if (filters.sort) params.set('sort', filters.sort);
      const result = await req<PaginatedResponse<OAuthClient>>(`/api/admin/clients?${params}`);
      return { ...result, items: (Array.isArray(result.items) ? result.items : []).map(normalizeOAuthClient) };
    },
    getClient: async (id: string) => normalizeOAuthClient(await req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}`, { cache: 'no-store' })),
    getClientInsights: (id: string, days = 30) => req<OAuthClientInsights>(`/api/admin/clients/${encodeURIComponent(id)}/insights?days=${days}`, { cache: 'no-store' }),
    getClientDiagnostics: (id: string, filters: OAuthDiagnosticFilters = {}) => {
      const params = new URLSearchParams({ page: String(filters.page || 1), page_size: String(filters.pageSize || 20) });
      if (filters.flow) params.set('flow', filters.flow);
      if (filters.stage) params.set('stage', filters.stage);
      if (filters.reason) params.set('reason', filters.reason);
      return req<PaginatedResponse<OAuthClientDiagnostic>>(`/api/admin/clients/${encodeURIComponent(id)}/diagnostics?${params}`, { cache: 'no-store' });
    },
    createClient: async (data: CreateClientInput) => normalizeOAuthClient(await req<CreateClientResult>('/api/admin/clients', { method: 'POST', body: JSON.stringify(data) })),
    updateClient: async (id: string, data: UpdateClientInput) => normalizeOAuthClient(await req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(data) })),
    uploadClientLogo: async (id: string, blob: Blob) => {
      const body = new FormData();
      body.append('logo', blob, blob.type === 'image/png' ? 'logo.png' : 'logo.webp');
      return normalizeOAuthClient(await req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}/logo`, { method: 'POST', body }));
    },
    removeClientLogo: async (id: string) => normalizeOAuthClient(await req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}/logo`, { method: 'DELETE' })),
    updateClientOwner: (id: string, data: { owner_id: string | null }) =>
      req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}/owner`, { method: 'PUT', body: JSON.stringify(data) }),
    verifyClientPublisher: (id: string) =>
      req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}/publisher-verification`, { method: 'POST' }),
    revokeClientPublisherVerification: (id: string) =>
      req<OAuthClient>(`/api/admin/clients/${encodeURIComponent(id)}/publisher-verification`, { method: 'DELETE' }),
    getClientAccessUsers: (id: string) => req<ClientAccessUser[]>(`/api/admin/clients/${encodeURIComponent(id)}/access-users`),
    updateClientAccessUsers: (id: string, userIDs: string[]) =>
      req<ClientAccessUser[]>(`/api/admin/clients/${encodeURIComponent(id)}/access-users`, { method: 'PUT', body: JSON.stringify({ user_ids: userIDs }) }),
    deleteClient: (id: string) => req<void>(`/api/admin/clients/${id}`, { method: 'DELETE' }),
    rotateClientSecret: (id: string) => req<RotateClientSecretResult>(`/api/admin/clients/${encodeURIComponent(id)}/rotate-secret`, { method: 'POST' }),
    getProviders: () => req<ExternalProvider[]>('/api/admin/providers'),
    createProvider: (data: CreateProviderInput) => req<ExternalProvider>('/api/admin/providers', { method: 'POST', body: JSON.stringify(data) }),
    updateProvider: (id: string, data: UpdateProviderInput) => req<ExternalProvider>(`/api/admin/providers/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(data) }),
    testProvider: (id: string) => req<ProviderTestResult>(`/api/admin/providers/${encodeURIComponent(id)}/test`, { method: 'POST' }),
    getProviderDiagnostics: (id: string, limit = 10) => req<ProviderDiagnosticRun[]>(`/api/admin/providers/${encodeURIComponent(id)}/diagnostics?limit=${limit}`, { cache: 'no-store' }),
    startProviderInteractiveDiagnostic: (id: string) => req<{ redirect_url: string }>(`/api/admin/providers/${encodeURIComponent(id)}/diagnostics/interactive`, { method: 'POST' }),
    deleteProvider: (id: string) => req<void>(`/api/admin/providers/${encodeURIComponent(id)}`, { method: 'DELETE' }),
    getAuditLogs: (filters: AuditLogFilters = {}) => {
      const params = buildAuditLogSearchParams(filters);
      return req<PaginatedResponse<AuditLog>>(`/api/admin/audit-logs?${params}`);
    },
    getAuditLogOptions: () => req<AuditLogOptions>('/api/admin/audit-logs/options'),
  },
};
