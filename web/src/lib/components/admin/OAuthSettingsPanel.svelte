<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type OAuthGrantType,
    type OAuthAssignmentPolicy,
    type OAuthRiskLevel,
    type OAuthScope,
    type OAuthScopeDefinition,
    type OAuthSettings,
    type UpdateOAuthSettingsInput,
  } from '$lib/api';
  import {
    DEFAULT_OAUTH_SETTINGS,
    OAUTH_GRANT_TYPES,
    OAUTH_SCOPES,
    oauthPolicyValidationError,
    oauthSettingsFromInput,
  } from '$lib/policy-settings';
  import { consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import FormField from '$lib/components/ui/FormField.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import FieldHelp from '$lib/components/ui/FieldHelp.svelte';
  import {
    ASSIGNMENT_LABELS,
    CLAIM_HELP,
    cloneScopeDefinitions,
    DEFAULT_SCOPE_DEFINITIONS,
    OAUTH_CLAIMS,
    RISK_LABELS,
    scopeHelp,
  } from '$lib/oauth-catalog';
  import { toast } from '$lib/toast';
  import { AppWindow, ChevronDown, Link2, Plus, ShieldCheck, Trash2 } from 'lucide-svelte';

  const returnTo = '/admin/settings/oauth';
  const pendingStorageKey = 'nyauth:reauth:oauth-settings';
  const grantLabels: Record<OAuthGrantType, string> = {
    authorization_code: 'Authorization Code',
    refresh_token: 'Refresh Token',
    client_credentials: 'Client Credentials',
  };
  const scopeLabels: Record<OAuthScope, string> = {
    openid: 'openid', profile: 'profile', email: 'email', offline_access: 'offline_access',
  };
  const assignmentOptions = Object.entries(ASSIGNMENT_LABELS).map(([value, label]) => ({ value, label }));
  const riskOptions = Object.entries(RISK_LABELS).map(([value, label]) => ({ value, label }));

  let settings = $state<OAuthSettings | null>(null);
  let draft = $state<OAuthSettings>({ ...DEFAULT_OAUTH_SETTINGS });
  let loading = $state(true);
  let saving = $state(false);
  let loadError = $state('');
  let error = $state('');
  let fieldErrors = $state<Record<string, string>>({});
  let conflict = $state(false);
  let reauthOpen = $state(false);
  let pendingInput = $state<UpdateOAuthSettingsInput | null>(null);
  let expandedScope = $state<string | null>(null);
  let claimPoliciesOpen = $state(false);
  let addScopeOpen = $state(false);
  let addScopeError = $state('');
  let newScopeName = $state('');
  let newScopeDisplayName = $state('');
  let newScopeDescription = $state('');
  let newScopeAssignment = $state<OAuthAssignmentPolicy>('admin_only');
  let newScopeRisk = $state<OAuthRiskLevel>('sensitive');
  let newScopeClaims = $state<string[]>([]);
  let customScopeList = $derived(draft.allowed_scopes.filter((scope) => !OAUTH_SCOPES.some((standard) => standard === scope)));
  let catalogScopes = $derived([
    ...OAUTH_SCOPES,
    ...customScopeList,
  ]);

  onMount(async () => {
    await loadSettings();
    await restorePending();
  });

  function applySettings(value: OAuthSettings) {
    settings = cloneSettings(value);
    draft = cloneSettings(value);
    expandedScope = null;
    error = '';
    fieldErrors = {};
    conflict = false;
  }

  function cloneSettings(value: OAuthSettings): OAuthSettings {
    return {
      ...value,
      allowed_grant_types: [...value.allowed_grant_types],
      allowed_scopes: [...value.allowed_scopes],
      scope_definitions: cloneScopeDefinitions(value.scope_definitions),
      claim_assignment_policies: { ...value.claim_assignment_policies },
    };
  }

  function fallbackScopeDefinition(scope: string): OAuthScopeDefinition {
    const standard = DEFAULT_SCOPE_DEFINITIONS[scope];
    if (standard) return { ...standard, claims: [...standard.claims] };
    return {
      display_name: scope,
      description: '由管理员定义的应用权限。',
      claims: [],
      assignment_policy: 'admin_only',
      risk_level: 'sensitive',
    };
  }

  function definitionFor(scope: string): OAuthScopeDefinition {
    return draft.scope_definitions[scope] || fallbackScopeDefinition(scope);
  }

  function updateDefinition(scope: string, patch: Partial<OAuthScopeDefinition>) {
    draft.scope_definitions = {
      ...draft.scope_definitions,
      [scope]: { ...definitionFor(scope), ...patch },
    };
  }

  function toggleDefinitionClaim(scope: string, claim: string, checked: boolean) {
    const selected = new Set(definitionFor(scope).claims);
    if (checked) selected.add(claim); else selected.delete(claim);
    updateDefinition(scope, { claims: OAUTH_CLAIMS.filter((item) => selected.has(item)) });
  }

  function updateClaimPolicy(claim: string, value: string) {
    draft.claim_assignment_policies = {
      ...draft.claim_assignment_policies,
      [claim]: value as OAuthAssignmentPolicy,
    };
  }

  async function loadSettings() {
    loading = true;
    loadError = '';
    try {
      applySettings(await api.admin.getOAuthSettings());
    } catch (cause) {
      settings = null;
      loadError = cause instanceof Error ? cause.message : 'OAuth 客户端策略加载失败';
    } finally {
      loading = false;
    }
  }

  function hasGrant(grant: OAuthGrantType) { return draft.allowed_grant_types.includes(grant); }
  function hasScope(scope: OAuthScope) { return draft.allowed_scopes.includes(scope); }

  function toggleGrant(grant: OAuthGrantType, checked: boolean) {
    const selected = new Set(draft.allowed_grant_types);
    if (checked) selected.add(grant); else selected.delete(grant);
    if (grant === 'authorization_code' && !checked) {
      selected.delete('refresh_token');
      draft.public_clients_enabled = false;
      draft.allowed_scopes = draft.allowed_scopes.filter((scope) => scope !== 'offline_access');
    }
    if (grant === 'refresh_token' && checked) selected.add('authorization_code');
    if (grant === 'refresh_token' && !checked) {
      draft.allowed_scopes = draft.allowed_scopes.filter((scope) => scope !== 'offline_access');
    }
    draft.allowed_grant_types = OAUTH_GRANT_TYPES.filter((item) => selected.has(item));
  }

  function toggleScope(scope: OAuthScope, checked: boolean) {
    const selected = new Set(draft.allowed_scopes);
    if (checked) selected.add(scope); else selected.delete(scope);
    draft.allowed_scopes = [
      ...OAUTH_SCOPES.filter((item) => selected.has(item)),
      ...draft.allowed_scopes.filter((item) => !OAUTH_SCOPES.some((standard) => standard === item)),
    ];
    if (scope === 'offline_access' && checked) toggleGrant('refresh_token', true);
  }

  function openAddScopeDialog() {
    newScopeName = '';
    newScopeDisplayName = '';
    newScopeDescription = '';
    newScopeAssignment = 'admin_only';
    newScopeRisk = 'sensitive';
    newScopeClaims = [];
    addScopeError = '';
    addScopeOpen = true;
  }

  function toggleNewScopeClaim(claim: string, checked: boolean) {
    const selected = new Set(newScopeClaims);
    if (checked) selected.add(claim); else selected.delete(claim);
    newScopeClaims = OAUTH_CLAIMS.filter((item) => selected.has(item));
  }

  function addCustomScope() {
    const scope = newScopeName.trim();
    const displayName = newScopeDisplayName.trim();
    const description = newScopeDescription.trim();
    if (!scope || !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope)) {
      addScopeError = 'Scope 标识必须是符合 OAuth 2.0 的可见 ASCII scope-token。';
      return;
    }
    if (draft.allowed_scopes.includes(scope) || OAUTH_SCOPES.some((standard) => standard === scope)) {
      addScopeError = `Scope ${scope} 已存在。`;
      return;
    }
    if (!displayName || displayName.length > 80) {
      addScopeError = '显示名称必填，且不能超过 80 个字符。';
      return;
    }
    if (!description || description.length > 300) {
      addScopeError = '授权说明必填，且不能超过 300 个字符。';
      return;
    }
    draft.allowed_scopes = [...draft.allowed_scopes, scope];
    updateDefinition(scope, {
      display_name: displayName,
      description,
      claims: [...newScopeClaims],
      assignment_policy: newScopeAssignment,
      risk_level: newScopeRisk,
    });
    expandedScope = scope;
    addScopeOpen = false;
  }

  function removeCustomScope(scope: string) {
    draft.allowed_scopes = draft.allowed_scopes.filter((item) => item !== scope);
    if (expandedScope === scope) expandedScope = null;
  }

  function toggleExpandedScope(scope: string) {
    expandedScope = expandedScope === scope ? null : scope;
  }

  function togglePublicClients(checked: boolean) {
    draft.public_clients_enabled = checked;
    if (checked) toggleGrant('authorization_code', true);
  }

  function buildInput(): UpdateOAuthSettingsInput | null {
    if (!settings) return null;
    const scopes = [
      ...OAUTH_SCOPES.filter((scope) => draft.allowed_scopes.includes(scope)),
      ...customScopeList,
    ];
    const definitions = Object.fromEntries(scopes.map((scope) => [scope, {
      ...definitionFor(scope),
      claims: [...definitionFor(scope).claims],
    }]));
    return {
      expected_revision: settings.revision,
      self_service_client_creation_enabled: draft.self_service_client_creation_enabled,
      public_clients_enabled: draft.public_clients_enabled,
      allowed_grant_types: [...draft.allowed_grant_types],
      allowed_scopes: scopes,
      scope_definitions: definitions,
      claim_assignment_policies: { ...draft.claim_assignment_policies },
      max_redirect_uris: draft.max_redirect_uris,
      max_post_logout_redirect_uris: draft.max_post_logout_redirect_uris,
    };
  }

  async function save(event: SubmitEvent) {
    event.preventDefault();
    const input = buildInput();
    if (!input) return;
    fieldErrors = {};
    const validation = oauthPolicyValidationError(input);
    if (validation) {
      fieldErrors = { [validation.field]: validation.message };
      error = validation.message;
      document.getElementById(validation.field)?.focus();
      return;
    }
    pendingInput = input;
    await executeSave(input, true);
  }

  async function executeSave(input: UpdateOAuthSettingsInput, allowReauthentication: boolean) {
    saving = true;
    error = '';
    conflict = false;
    try {
      const updated = await api.admin.updateOAuthSettings(input);
      pendingInput = null;
      applySettings(updated);
      toast.success('OAuth 客户端策略已保存，立即约束后续创建和扩展操作。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
        return;
      }
      if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        conflict = true;
        error = '设置已被其他管理员修改。当前草稿已保留，请加载最新设置后重新核对。';
        return;
      }
      toast.error(cause instanceof Error ? cause.message : 'OAuth 客户端策略保存失败');
    } finally {
      saving = false;
    }
  }

  function persistPending() {
    if (pendingInput) sessionStorage.setItem(pendingStorageKey, JSON.stringify(pendingInput));
  }

  async function restorePending() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored = JSON.parse(raw) as UpdateOAuthSettingsInput;
      const validation = oauthPolicyValidationError(restored);
      if (validation || !Number.isSafeInteger(restored.expected_revision)) throw new TypeError('invalid stored OAuth policy');
      pendingInput = restored;
      settings = cloneSettings(oauthSettingsFromInput(restored));
      draft = cloneSettings(oauthSettingsFromInput(restored));
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      await executeSave(restored, false);
    } catch {
      toast.error('无法恢复待保存的 OAuth 客户端策略，请重新检查设置。');
    }
  }
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-3">
    <span class="flex h-10 w-10 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><AppWindow size={18} /></span>
    <div><h2 class="text-card-title text-nya-text-primary">OAuth 客户端策略</h2><p class="mt-1 text-small text-nya-text-secondary">控制后续客户端注册能力，不会静默停用已经存在的客户端。</p></div>
  </div>

  {#if loading}
    <p class="text-small text-nya-text-tertiary" role="status">正在加载 OAuth 客户端策略…</p>
  {:else if !settings}
    <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger" role="alert">{loadError}</p><Button variant="ghost" size="sm" onclick={loadSettings}>重试</Button></div>
  {:else}
    <form onsubmit={save} class="space-y-5">
      {#if error}<div class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><p>{error}</p>{#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}>加载最新设置</Button>{/if}</div>{/if}

      <div class="space-y-4 rounded-nya-sm bg-nya-surface-muted p-4">
        <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div class="max-w-2xl"><p class="font-semibold text-nya-text-primary">允许用户自助创建客户端</p><p class="mt-1 text-small text-nya-text-secondary">关闭后用户仍可查看、轮换 Secret 和删除既有客户端，只有新建入口被关闭。</p></div><Switch checked={draft.self_service_client_creation_enabled} onchange={(checked) => (draft.self_service_client_creation_enabled = checked)} label="允许自助创建" /></div>
        <div class="border-t border-nya-divider pt-4"><div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start"><div class="max-w-2xl"><p class="font-semibold text-nya-text-primary">允许新建 Public Client</p><p class="mt-1 text-small text-nya-text-secondary">适用于无法安全保存 Secret 的原生应用。关闭后不会停用已有 Public Client。</p></div><Switch checked={draft.public_clients_enabled} onchange={togglePublicClients} label="允许 Public Client" /></div>{#if fieldErrors['oauth-public-clients']}<p class="mt-2 text-small text-nya-danger">{fieldErrors['oauth-public-clients']}</p>{/if}</div>
      </div>

      <fieldset id="oauth-grants" tabindex="-1" class="rounded-nya-sm border border-nya-border p-4">
        <legend class="flex items-center gap-2 px-1 font-semibold text-nya-text-primary"><ShieldCheck size={16} class="text-nya-primary" /> 允许的 Grant</legend>
        <div class="mt-2 grid gap-3 sm:grid-cols-3">{#each OAUTH_GRANT_TYPES as grant}<label class="flex items-center gap-2 text-body text-nya-text-primary"><input type="checkbox" checked={hasGrant(grant)} onchange={(event) => toggleGrant(grant, event.currentTarget.checked)} /> {grantLabels[grant]}</label>{/each}</div>
        {#if fieldErrors['oauth-grants']}<p class="mt-2 text-small text-nya-danger">{fieldErrors['oauth-grants']}</p>{/if}
      </fieldset>

      <fieldset id="oauth-scopes" tabindex="-1" class="rounded-nya-sm border border-nya-border p-4">
        <legend class="flex items-center gap-2 px-1 font-semibold text-nya-text-primary"><ShieldCheck size={16} class="text-nya-primary" /> Scope 目录</legend>
        <div class="mt-1 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <p class="max-w-2xl text-small text-nya-text-secondary">在同一目录中启停标准 Scope、维护授权页文案和控制 Claim。各项默认收起，只展开当前正在编辑的一项。</p>
          <Button variant="secondary" size="sm" onclick={openAddScopeDialog}><Plus size={15} /> 添加自定义 Scope</Button>
        </div>

        <div class="mt-4 overflow-hidden rounded-nya-sm border border-nya-border">
          {#each catalogScopes as scope}
            {@const definition = definitionFor(scope)}
            {@const standard = OAUTH_SCOPES.some((item) => item === scope)}
            {@const expanded = expandedScope === scope}
            <section class="border-b border-nya-divider last:border-b-0" data-scope={scope}>
              <div class="flex flex-col gap-3 px-3 py-3 sm:flex-row sm:items-center sm:justify-between">
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    {#if standard}
                      <label class="flex items-center gap-2 text-small text-nya-text-primary"><input type="checkbox" checked={hasScope(scope as OAuthScope)} onchange={(event) => toggleScope(scope as OAuthScope, event.currentTarget.checked)} /><code class="font-semibold">{scopeLabels[scope as OAuthScope]}</code></label>
                    {:else}
                      <code class="font-semibold text-nya-text-primary">{scope}</code>
                    {/if}
                    <span class="truncate text-small text-nya-text-secondary">{definition.display_name}</span>
                    <span class="rounded-full bg-nya-surface-muted px-2 py-0.5 text-micro text-nya-text-tertiary">{standard ? '标准' : '自定义'}</span>
                    {#if standard && !hasScope(scope as OAuthScope)}<span class="rounded-full bg-nya-warning-soft px-2 py-0.5 text-micro text-nya-warning">已停用</span>{/if}
                  </div>
                  <p class="mt-1 truncate text-micro text-nya-text-tertiary">{ASSIGNMENT_LABELS[definition.assignment_policy]} · {RISK_LABELS[definition.risk_level]} · {definition.claims.length > 0 ? `${definition.claims.length} 个 Claim` : '无身份字段'}</p>
                </div>
                <div class="flex shrink-0 items-center justify-between gap-2 sm:justify-end">
                  <FieldHelp id={`oauth-catalog-${scope}-help`} text={scopeHelp(definition)} label={`查看 ${scope} 的完整权限说明`} />
                  <button type="button" aria-expanded={expanded} aria-controls={`oauth-scope-${scope}-editor`} aria-label={expanded ? `收起 ${scope} 配置` : `展开 ${scope} 配置`} title={expanded ? '收起配置' : '编辑配置'} onclick={() => toggleExpandedScope(scope)} class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-tertiary hover:bg-nya-surface-muted hover:text-nya-primary"><ChevronDown size={16} class="transition-transform {expanded ? 'rotate-180' : ''}" /></button>
                </div>
              </div>

              {#if expanded}
                <div id={`oauth-scope-${scope}-editor`} class="border-t border-nya-divider bg-nya-surface-muted px-3 py-4 sm:px-4">
                  <div class="grid gap-3 md:grid-cols-2">
                    <FormField id={`oauth-scope-${scope}-name`} label="显示名称"><input id={`oauth-scope-${scope}-name`} value={definition.display_name} oninput={(event) => updateDefinition(scope, { display_name: event.currentTarget.value })} maxlength="80" class="h-[38px] w-full rounded-nya-sm border border-nya-border-strong bg-nya-surface px-3 text-body focus:outline-none focus:ring-2 focus:ring-nya-primary/24" /></FormField>
                    <FormField id={`oauth-scope-${scope}-description`} label="授权说明"><input id={`oauth-scope-${scope}-description`} value={definition.description} oninput={(event) => updateDefinition(scope, { description: event.currentTarget.value })} maxlength="300" class="h-[38px] w-full rounded-nya-sm border border-nya-border-strong bg-nya-surface px-3 text-body focus:outline-none focus:ring-2 focus:ring-nya-primary/24" /></FormField>
                  </div>
                  <div class="mt-3 grid gap-3 lg:grid-cols-2">
                    <div><p class="mb-2 text-small font-semibold text-nya-text-secondary">分配权限</p><div class="inline-flex rounded-nya-sm border border-nya-border bg-nya-surface p-1">{#each assignmentOptions as option}<button type="button" onclick={() => updateDefinition(scope, { assignment_policy: option.value as OAuthAssignmentPolicy })} class="rounded-nya-xs px-3 py-1.5 text-small {definition.assignment_policy === option.value ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-muted'}">{option.label}</button>{/each}</div></div>
                    <div><p class="mb-2 text-small font-semibold text-nya-text-secondary">风险等级</p><div class="inline-flex flex-wrap rounded-nya-sm border border-nya-border bg-nya-surface p-1">{#each riskOptions as option}<button type="button" onclick={() => updateDefinition(scope, { risk_level: option.value as OAuthRiskLevel })} class="rounded-nya-xs px-3 py-1.5 text-small {definition.risk_level === option.value ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-muted'}">{option.label}</button>{/each}</div></div>
                  </div>
                  <div class="mt-3"><p class="mb-2 text-small font-semibold text-nya-text-secondary">返回的 Claim</p><div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{#each OAUTH_CLAIMS as claim}<div class="flex items-center justify-between gap-2 rounded-nya-xs bg-nya-surface px-2 py-1.5 text-small text-nya-text-primary"><label class="flex min-w-0 items-center gap-2"><input type="checkbox" checked={definition.claims.includes(claim)} disabled={standard} onchange={(event) => toggleDefinitionClaim(scope, claim, event.currentTarget.checked)} /><span>{CLAIM_HELP[claim]?.title || claim}</span></label><FieldHelp id={`oauth-${scope}-${claim}-help`} text={CLAIM_HELP[claim]?.description || claim} label={`查看 ${claim} Claim 说明`} /></div>{/each}</div>{#if standard}<p class="mt-2 text-micro text-nya-text-tertiary">标准 Scope 的 Claim 映射遵循 OIDC 语义，不能改写。</p>{/if}</div>
                  {#if !standard}
                    <div class="mt-4 flex flex-col gap-3 border-t border-nya-divider pt-3 sm:flex-row sm:items-center sm:justify-between"><p class="text-micro text-nya-text-tertiary">停止新分配后会从 Discovery 隐藏，但既有客户端继续使用最后一版定义。</p><Button variant="ghost" size="sm" onclick={() => removeCustomScope(scope)}><Trash2 size={14} /> 停止新分配</Button></div>
                  {/if}
                </div>
              {/if}
            </section>
          {/each}
        </div>
        {#if fieldErrors['oauth-scopes']}<p class="mt-2 text-small text-nya-danger">{fieldErrors['oauth-scopes']}</p>{/if}
      </fieldset>

      <fieldset class="rounded-nya-sm border border-nya-border p-4">
        <legend class="px-1 font-semibold text-nya-text-primary">Claim 分配权限</legend>
        <button type="button" aria-expanded={claimPoliciesOpen} aria-controls="oauth-claim-policies" onclick={() => (claimPoliciesOpen = !claimPoliciesOpen)} class="flex w-full items-start justify-between gap-3 text-left">
          <span class="text-small text-nya-text-secondary">控制哪些字段可以由普通客户端所有者自行选择；管理员专属字段仍会在 Consent 中如实展示。</span>
          <ChevronDown size={16} class="mt-0.5 shrink-0 text-nya-text-tertiary transition-transform {claimPoliciesOpen ? 'rotate-180' : ''}" />
        </button>
        {#if claimPoliciesOpen}
          <div id="oauth-claim-policies" class="mt-3 grid gap-2 md:grid-cols-2">
            {#each OAUTH_CLAIMS as claim}
              <div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-surface-muted px-3 py-2">
                <div class="flex items-center gap-2"><code class="text-small text-nya-text-primary">{claim}</code><FieldHelp id={`oauth-claim-${claim}-help`} text={CLAIM_HELP[claim]?.description || claim} label={`查看 ${claim} Claim 说明`} /></div>
                <div class="inline-flex rounded-nya-sm border border-nya-border bg-nya-surface p-0.5">{#each assignmentOptions as option}<button type="button" disabled={claim === 'sub'} onclick={() => updateClaimPolicy(claim, option.value)} class="rounded-nya-xs px-2 py-1 text-micro disabled:cursor-not-allowed disabled:opacity-50 {draft.claim_assignment_policies[claim] === option.value ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary'}">{option.label}</button>{/each}</div>
              </div>
            {/each}
          </div>
        {/if}
      </fieldset>

      <fieldset class="border-t border-nya-divider pt-5">
        <legend class="flex items-center gap-2 font-semibold text-nya-text-primary"><Link2 size={16} class="text-nya-primary" /> URI 数量上限</legend>
        <div class="mt-3 grid gap-4 sm:grid-cols-2">
          <FormField id="oauth-max-redirects" label="Redirect URI 上限" error={fieldErrors['oauth-max-redirects']} hint="每个客户端 1–100 个。"><input id="oauth-max-redirects" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body" type="number" min="1" max="100" bind:value={draft.max_redirect_uris} /></FormField>
          <FormField id="oauth-max-logouts" label="Post-logout Redirect URI 上限" error={fieldErrors['oauth-max-logouts']} hint="每个客户端 0–100 个；0 表示禁止新登记退出回跳地址。"><input id="oauth-max-logouts" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body" type="number" min="0" max="100" bind:value={draft.max_post_logout_redirect_uris} /></FormField>
        </div>
      </fieldset>

      <div class="rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info">收紧策略只影响新建和扩展操作。已有客户端可继续运行，也可以保留原值、替换同数量 URI 或逐步减少到新上限。</div>
      <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存 OAuth 客户端策略</Button>
    </form>
  {/if}
</section>

<Modal bind:open={addScopeOpen} title="添加自定义 Scope" description="一次填写完整定义；添加后仍可在目录中继续编辑。" size="lg">
  <div class="space-y-4">
    {#if addScopeError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{addScopeError}</p>{/if}
    <div class="grid gap-3 md:grid-cols-2">
      <FormField id="oauth-new-scope-name" label="Scope 标识" hint="例如 api.read；创建后不能通过重命名替代旧 Scope。"><input id="oauth-new-scope-name" bind:value={newScopeName} autocomplete="off" spellcheck="false" placeholder="api.read" class="h-[38px] w-full rounded-nya-sm border border-nya-border-strong bg-nya-surface px-3 font-mono text-body focus:outline-none focus:ring-2 focus:ring-nya-primary/24" /></FormField>
      <FormField id="oauth-new-scope-display-name" label="Scope 显示名称"><input id="oauth-new-scope-display-name" bind:value={newScopeDisplayName} maxlength="80" placeholder="读取业务数据" class="h-[38px] w-full rounded-nya-sm border border-nya-border-strong bg-nya-surface px-3 text-body focus:outline-none focus:ring-2 focus:ring-nya-primary/24" /></FormField>
    </div>
    <FormField id="oauth-new-scope-description" label="授权说明" hint="这段说明会直接显示在用户授权确认页。"><input id="oauth-new-scope-description" bind:value={newScopeDescription} maxlength="300" placeholder="允许应用读取当前账户可访问的业务数据。" class="h-[38px] w-full rounded-nya-sm border border-nya-border-strong bg-nya-surface px-3 text-body focus:outline-none focus:ring-2 focus:ring-nya-primary/24" /></FormField>
    <div class="grid gap-4 md:grid-cols-2">
      <div><p class="mb-2 text-small font-semibold text-nya-text-secondary">分配权限</p><div class="inline-flex rounded-nya-sm border border-nya-border bg-nya-surface p-1">{#each assignmentOptions as option}<button type="button" onclick={() => (newScopeAssignment = option.value as OAuthAssignmentPolicy)} class="rounded-nya-xs px-3 py-1.5 text-small {newScopeAssignment === option.value ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-muted'}">{option.label}</button>{/each}</div></div>
      <div><p class="mb-2 text-small font-semibold text-nya-text-secondary">风险等级</p><div class="inline-flex flex-wrap rounded-nya-sm border border-nya-border bg-nya-surface p-1">{#each riskOptions as option}<button type="button" onclick={() => (newScopeRisk = option.value as OAuthRiskLevel)} class="rounded-nya-xs px-3 py-1.5 text-small {newScopeRisk === option.value ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary hover:bg-nya-surface-muted'}">{option.label}</button>{/each}</div></div>
    </div>
    <div>
      <p class="mb-2 text-small font-semibold text-nya-text-secondary">返回的 Claim</p>
      <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {#each OAUTH_CLAIMS as claim}
          <div class="flex items-center justify-between gap-2 rounded-nya-xs bg-nya-surface-muted px-2 py-1.5 text-small text-nya-text-primary"><label class="flex min-w-0 items-center gap-2"><input type="checkbox" checked={newScopeClaims.includes(claim)} disabled={claim === 'sub'} onchange={(event) => toggleNewScopeClaim(claim, event.currentTarget.checked)} /><span>{CLAIM_HELP[claim]?.title || claim}</span></label><FieldHelp id={`oauth-new-${claim}-help`} text={claim === 'sub' ? 'sub 只能由标准 openid Scope 返回。' : CLAIM_HELP[claim]?.description || claim} label={`查看 ${claim} Claim 说明`} /></div>
        {/each}
      </div>
    </div>
    <div class="flex justify-end gap-2 border-t border-nya-divider pt-4"><Button variant="ghost" onclick={() => (addScopeOpen = false)}>取消</Button><Button variant="primary" onclick={addCustomScope}><Plus size={15} /> 添加到目录</Button></div>
  </div>
</Modal>

<ReauthenticationDialog bind:open={reauthOpen} {returnTo} description="修改 OAuth 客户端策略前需要验证近期身份" onauthenticated={async () => { if (pendingInput) await executeSave(pendingInput, false); }} onbeforeprovider={persistPending} />
