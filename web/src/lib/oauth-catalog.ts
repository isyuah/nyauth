import type {
  OAuthAssignmentPolicy,
  OAuthClientPolicy,
  OAuthRiskLevel,
  OAuthScopeDefinition,
} from './api';

export const OAUTH_CLAIMS = [
  'sub',
  'preferred_username',
  'name',
  'picture',
  'email',
  'email_verified',
  'role',
] as const;

export const CLAIM_HELP: Record<string, { title: string; description: string }> = {
  sub: { title: '稳定用户 ID', description: '面向当前 Nyauth 发行方的稳定用户标识。' },
  preferred_username: { title: '用户名', description: '用户用于登录和识别账户的用户名。' },
  name: { title: '显示名称', description: '用户设置的公开显示名称。' },
  picture: { title: '头像', description: '由 Nyauth 管理的同源头像地址。' },
  email: { title: '邮箱地址', description: '当前账户绑定的邮箱地址。' },
  email_verified: { title: '邮箱验证状态', description: '表示邮箱是否已经由 Nyauth 完成验证。' },
  role: { title: '账户角色', description: '用户在 Nyauth 中的管理员或普通用户角色。' },
};

export const ASSIGNMENT_LABELS: Record<OAuthAssignmentPolicy, string> = {
  self_service: '允许自助分配',
  admin_only: '仅管理员分配',
};

export const RISK_LABELS: Record<OAuthRiskLevel, string> = {
  low: '低风险',
  personal_data: '个人数据',
  sensitive: '敏感权限',
};

export const DEFAULT_SCOPE_DEFINITIONS: Record<string, OAuthScopeDefinition> = {
  openid: {
    display_name: '确认身份',
    description: '使用稳定的账户标识完成 OpenID Connect 登录。',
    claims: ['sub'],
    assignment_policy: 'self_service',
    risk_level: 'low',
  },
  profile: {
    display_name: '基本资料',
    description: '读取用户名、显示名称和头像。',
    claims: ['preferred_username', 'name', 'picture'],
    assignment_policy: 'self_service',
    risk_level: 'personal_data',
  },
  email: {
    display_name: '邮箱信息',
    description: '读取邮箱地址及邮箱验证状态。',
    claims: ['email', 'email_verified'],
    assignment_policy: 'self_service',
    risk_level: 'personal_data',
  },
  offline_access: {
    display_name: '离线访问',
    description: '允许应用在用户离开后使用可轮换的 Refresh Token 继续访问。',
    claims: [],
    assignment_policy: 'self_service',
    risk_level: 'sensitive',
  },
};

export const DEFAULT_CLAIM_ASSIGNMENT_POLICIES: Record<string, OAuthAssignmentPolicy> = {
  sub: 'self_service',
  preferred_username: 'self_service',
  name: 'self_service',
  picture: 'self_service',
  email: 'self_service',
  email_verified: 'self_service',
  role: 'admin_only',
};

export function cloneScopeDefinitions(
  definitions: Record<string, OAuthScopeDefinition>,
): Record<string, OAuthScopeDefinition> {
  return Object.fromEntries(Object.entries(definitions).map(([scope, definition]) => [scope, {
    ...definition,
    claims: [...definition.claims],
  }]));
}

export function claimsForScopes(
  policy: OAuthClientPolicy,
  scopes: string[],
  administrator: boolean,
): string[] {
  const selected = new Set<string>();
  for (const scope of scopes) {
    const definition = policy.scope_definitions[scope];
    if (!definition) continue;
    for (const claim of definition.claims) {
      if (administrator || policy.claim_assignment_policies[claim] !== 'admin_only') selected.add(claim);
    }
  }
  return OAUTH_CLAIMS.filter((claim) => selected.has(claim));
}

export function scopeHelp(definition: OAuthScopeDefinition): string {
  const claims = definition.claims.map((claim) => CLAIM_HELP[claim]?.title || claim);
  const claimSummary = claims.length > 0 ? `返回：${claims.join('、')}。` : '不直接返回身份字段。';
  return `${definition.description} ${claimSummary}${ASSIGNMENT_LABELS[definition.assignment_policy]}，${RISK_LABELS[definition.risk_level]}。`;
}
