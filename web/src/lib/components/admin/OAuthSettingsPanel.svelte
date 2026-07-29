<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type OAuthGrantType,
    type OAuthScope,
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
  import Switch from '$lib/components/ui/Switch.svelte';
  import { toast } from '$lib/toast';
  import { AppWindow, Link2, ShieldCheck } from 'lucide-svelte';

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
  let customScopes = $state('');

  onMount(async () => {
    await loadSettings();
    await restorePending();
  });

  function applySettings(value: OAuthSettings) {
    settings = { ...value, allowed_grant_types: [...value.allowed_grant_types], allowed_scopes: [...value.allowed_scopes] };
    draft = { ...value, allowed_grant_types: [...value.allowed_grant_types], allowed_scopes: [...value.allowed_scopes] };
    customScopes = value.allowed_scopes.filter((scope) => !OAUTH_SCOPES.some((standard) => standard === scope)).join('\n');
    error = '';
    fieldErrors = {};
    conflict = false;
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

  function customScopeValues(): string[] {
    return customScopes.split('\n').map((scope) => scope.trim()).filter(Boolean);
  }

  function togglePublicClients(checked: boolean) {
    draft.public_clients_enabled = checked;
    if (checked) toggleGrant('authorization_code', true);
  }

  function buildInput(): UpdateOAuthSettingsInput | null {
    if (!settings) return null;
    return {
      expected_revision: settings.revision,
      self_service_client_creation_enabled: draft.self_service_client_creation_enabled,
      public_clients_enabled: draft.public_clients_enabled,
      allowed_grant_types: [...draft.allowed_grant_types],
      allowed_scopes: [
        ...OAUTH_SCOPES.filter((scope) => draft.allowed_scopes.includes(scope)),
        ...customScopeValues(),
      ],
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
      settings = oauthSettingsFromInput(restored);
      draft = oauthSettingsFromInput(restored);
      customScopes = restored.allowed_scopes.filter((scope) => !OAUTH_SCOPES.some((standard) => standard === scope)).join('\n');
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
        <legend class="flex items-center gap-2 px-1 font-semibold text-nya-text-primary"><ShieldCheck size={16} class="text-nya-primary" /> 允许的标准 Scope</legend>
        <div class="mt-2 grid gap-3 sm:grid-cols-4">{#each OAUTH_SCOPES as scope}<label class="flex items-center gap-2 font-mono text-small text-nya-text-primary"><input type="checkbox" checked={hasScope(scope)} onchange={(event) => toggleScope(scope, event.currentTarget.checked)} /> {scopeLabels[scope]}</label>{/each}</div>
        <div class="mt-4"><label for="oauth-custom-scopes" class="mb-1.5 block text-body-medium text-nya-text-primary">自定义 Scope <span class="text-small text-nya-text-tertiary">（每行一个）</span></label><textarea id="oauth-custom-scopes" bind:value={customScopes} rows="3" spellcheck="false" placeholder="api.read&#10;api.write" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea><p class="mt-1 text-micro text-nya-text-tertiary">仅影响之后新增或扩展的客户端；删除某项不会从既有客户端中移除。</p></div>
        {#if fieldErrors['oauth-scopes']}<p class="mt-2 text-small text-nya-danger">{fieldErrors['oauth-scopes']}</p>{/if}
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

<ReauthenticationDialog bind:open={reauthOpen} {returnTo} description="修改 OAuth 客户端策略前需要验证近期身份" onauthenticated={async () => { if (pendingInput) await executeSave(pendingInput, false); }} onbeforeprovider={persistPending} />
