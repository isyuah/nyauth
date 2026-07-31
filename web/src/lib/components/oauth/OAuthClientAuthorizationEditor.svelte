<script lang="ts">
  import type { OAuthClientPolicy, OAuthGrantType, OAuthScope } from '$lib/api';
  import { CLAIM_HELP, OAUTH_CLAIMS, claimsForScopes, scopeHelp } from '$lib/oauth-catalog';
  import Badge from '$lib/components/ui/Badge.svelte';
  import FieldHelp from '$lib/components/ui/FieldHelp.svelte';

  const grantOptions: Array<{ value: OAuthGrantType; label: string; description: string }> = [
    { value: 'authorization_code', label: 'Authorization Code', description: '由用户授权并使用 PKCE 换取 Token。' },
    { value: 'refresh_token', label: 'Refresh Token', description: '允许客户端轮换凭据并延续用户授权。' },
    { value: 'client_credentials', label: 'Client Credentials', description: '用于没有用户参与的服务端机器身份。' },
  ];

  let {
    policy,
    idPrefix,
    administrator = true,
    isPublic = false,
    grants = $bindable(),
    scopes = $bindable(),
    optionalScopes = $bindable(),
    allowedClaims = $bindable(),
    existingGrants = [],
    existingScopes = [],
    existingClaims = [],
    onAuthorizationCodeDisabled,
  }: {
    policy: OAuthClientPolicy;
    idPrefix: string;
    administrator?: boolean;
    isPublic?: boolean;
    grants: OAuthGrantType[];
    scopes: OAuthScope[];
    optionalScopes: OAuthScope[];
    allowedClaims: string[];
    existingGrants?: string[];
    existingScopes?: OAuthScope[];
    existingClaims?: string[];
    onAuthorizationCodeDisabled?: () => void;
  } = $props();

  let scopeOptions = $derived([...new Set([...policy.allowed_scopes, ...existingScopes])]);
  let availableClaims = $derived(claimsForScopes(policy, scopes, administrator));
  let claimOptions = $derived([
    ...OAUTH_CLAIMS.filter((claim) => availableClaims.includes(claim) || existingClaims.includes(claim)),
    ...existingClaims.filter((claim) => !OAUTH_CLAIMS.includes(claim as typeof OAUTH_CLAIMS[number])),
  ]);
  let authorizationCodeSelected = $derived(grants.includes('authorization_code'));

  function grantCanBeAdded(grant: OAuthGrantType): boolean {
    return policy.allowed_grant_types.includes(grant);
  }

  function toggleGrant(grant: OAuthGrantType, checked: boolean) {
    if (checked && !grantCanBeAdded(grant)) return;
    const selected = new Set(grants);
    if (checked) selected.add(grant); else selected.delete(grant);
    if (grant === 'authorization_code' && !checked) {
      selected.delete('refresh_token');
      optionalScopes = [];
      onAuthorizationCodeDisabled?.();
    }
    if (grant === 'refresh_token' && checked) selected.add('authorization_code');
    if (grant === 'refresh_token' && !checked) {
      scopes = scopes.filter((scope) => scope !== 'offline_access');
      optionalScopes = optionalScopes.filter((scope) => scope !== 'offline_access');
    }
    grants = grantOptions.map((option) => option.value).filter((value) => selected.has(value));
  }

  function scopeCanBeAdded(scope: string): boolean {
    const definition = policy.scope_definitions[scope];
    return policy.allowed_scopes.includes(scope)
      && (administrator || definition?.assignment_policy !== 'admin_only');
  }

  function toggleScope(scope: OAuthScope, checked: boolean) {
    if (checked && !scopeCanBeAdded(scope)) return;
    const previousAvailableClaims = claimsForScopes(policy, scopes, administrator);
    const selected = new Set(scopes);
    if (checked) selected.add(scope); else selected.delete(scope);
    const nextScopes = scopeOptions.filter((value) => selected.has(value));
    scopes = nextScopes;
    if (!checked) optionalScopes = optionalScopes.filter((value) => value !== scope);

    const nextAvailableClaims = claimsForScopes(policy, nextScopes, administrator);
    const selectedClaims = new Set(allowedClaims);
    if (checked) {
      for (const claim of policy.scope_definitions[scope]?.claims || []) {
        if (administrator || policy.claim_assignment_policies[claim] !== 'admin_only') selectedClaims.add(claim);
      }
    }
    const preservedClaims = new Set(existingClaims);
    allowedClaims = [...new Set([...nextAvailableClaims, ...existingClaims])].filter((claim) =>
      selectedClaims.has(claim) && (nextAvailableClaims.includes(claim) || (preservedClaims.has(claim) && !previousAvailableClaims.includes(claim)))
    );
    if (!nextScopes.includes('openid')) allowedClaims = allowedClaims.filter((claim) => claim !== 'sub');
    if (nextScopes.includes('openid') && !allowedClaims.includes('sub')) allowedClaims = ['sub', ...allowedClaims];
    if (scope === 'offline_access' && checked) toggleGrant('refresh_token', true);
  }

  function toggleOptionalScope(scope: OAuthScope, checked: boolean) {
    if (scope === 'openid' || !scopes.includes(scope) || !authorizationCodeSelected) return;
    const selected = new Set(optionalScopes);
    if (checked) selected.add(scope); else selected.delete(scope);
    optionalScopes = scopes.filter((value) => value !== 'openid' && selected.has(value));
  }

  function claimCanBeAdded(claim: string): boolean {
    return availableClaims.includes(claim);
  }

  function toggleClaim(claim: string, checked: boolean) {
    if (checked && !claimCanBeAdded(claim)) return;
    const selected = new Set(allowedClaims);
    if (checked) selected.add(claim); else selected.delete(claim);
    allowedClaims = claimOptions.filter((value) => selected.has(value));
    if (scopes.includes('openid') && !allowedClaims.includes('sub')) allowedClaims = ['sub', ...allowedClaims];
  }
</script>

<fieldset class="rounded-nya-sm border border-nya-border p-3">
  <legend class="px-1 text-body-medium text-nya-text-primary">Grant</legend>
  <div class="grid gap-2 sm:grid-cols-3">
    {#each grantOptions.filter((option) => policy.allowed_grant_types.includes(option.value) || existingGrants.includes(option.value)) as option}
      {@const selected = grants.includes(option.value)}
      {@const policyDisabled = !grantCanBeAdded(option.value)}
      <label class="flex min-h-16 cursor-pointer items-start gap-2 rounded-nya-sm border border-nya-border px-3 py-2 hover:bg-nya-surface-soft">
        <input
          type="checkbox"
          checked={selected}
          disabled={(isPublic && option.value === 'client_credentials') || (policyDisabled && !selected)}
          onchange={(event) => toggleGrant(option.value, event.currentTarget.checked)}
          class="mt-0.5"
        />
        <span class="min-w-0">
          <span class="flex flex-wrap items-center gap-1.5 text-small font-semibold text-nya-text-primary">
            {option.label}
            {#if policyDisabled}<Badge variant="warning">现有 · 策略已关闭</Badge>{/if}
          </span>
          <span class="mt-0.5 block text-micro text-nya-text-tertiary">{option.description}</span>
        </span>
      </label>
    {/each}
  </div>
</fieldset>

<fieldset class="rounded-nya-sm border border-nya-border p-3">
  <legend class="px-1 text-body-medium text-nya-text-primary">Scope</legend>
  <div class="space-y-2">
    {#each scopeOptions as scope}
      {@const definition = policy.scope_definitions[scope]}
      {@const selected = scopes.includes(scope)}
      {@const policyDisabled = !scopeCanBeAdded(scope)}
      <div class="grid min-h-12 grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-nya-xs px-2 py-1.5 hover:bg-nya-surface-soft">
        <div class="flex min-w-0 items-start gap-2">
          <input
            id={`${idPrefix}-scope-${scope}`}
            class="mt-1"
            type="checkbox"
            checked={selected}
            disabled={policyDisabled && !selected}
            onchange={(event) => toggleScope(scope, event.currentTarget.checked)}
          />
          <label for={`${idPrefix}-scope-${scope}`} class="min-w-0 cursor-pointer">
            <span class="flex flex-wrap items-center gap-1.5 text-small text-nya-text-primary">
              <code>{scope}</code>
              {#if definition?.assignment_policy === 'admin_only'}<Badge variant="warning">仅管理员</Badge>{/if}
              {#if policyDisabled}<Badge variant="warning">现有 · 策略已关闭</Badge>{/if}
            </span>
            <span class="mt-0.5 block text-micro text-nya-text-tertiary">{definition?.display_name || '既有自定义 Scope'}</span>
          </label>
          <FieldHelp
            id={`${idPrefix}-scope-${scope}-help`}
            text={definition ? scopeHelp(definition) : '此 Scope 来自既有客户端配置，当前策略已不再提供其定义；可以保留或移除，但移除后不能重新添加。'}
            label={`查看 ${scope} Scope 说明`}
          />
        </div>
        {#if scope === 'openid'}
          <span class="text-micro text-nya-text-tertiary">OIDC 身份必需</span>
        {:else}
          <label class="flex items-center gap-2 text-small text-nya-text-secondary">
            <input
              type="checkbox"
              aria-label={`${scope} 允许用户拒绝`}
              checked={optionalScopes.includes(scope)}
              disabled={!selected || !authorizationCodeSelected}
              onchange={(event) => toggleOptionalScope(scope, event.currentTarget.checked)}
            />
            允许用户拒绝
          </label>
        {/if}
      </div>
    {/each}
  </div>
  <p class="mt-2 text-micro text-nya-text-tertiary">可选 Scope 会在授权页逐项展示；应用必须能够处理用户拒绝部分权限后的 Token。</p>
</fieldset>

<fieldset class="rounded-nya-sm border border-nya-border p-3">
  <legend class="px-1 text-body-medium text-nya-text-primary">允许返回的 Claim</legend>
  <div class="grid gap-2 sm:grid-cols-2">
    {#each claimOptions as claim}
      {@const selected = allowedClaims.includes(claim)}
      {@const available = claimCanBeAdded(claim)}
      {@const requiredSub = claim === 'sub' && scopes.includes('openid')}
      <div class="grid min-h-12 grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2 rounded-nya-xs px-2 py-1.5 text-nya-text-secondary hover:bg-nya-surface-soft">
        <input
          id={`${idPrefix}-claim-${claim}`}
          class="mt-1"
          type="checkbox"
          checked={selected}
          disabled={requiredSub || (!available && !selected)}
          onchange={(event) => toggleClaim(claim, event.currentTarget.checked)}
        />
        <label for={`${idPrefix}-claim-${claim}`} class="min-w-0 cursor-pointer">
          <span class="flex flex-wrap items-center gap-1.5 text-small text-nya-text-secondary">
            <span>{CLAIM_HELP[claim]?.title || claim}</span>
            {#if !available}<Badge variant="warning">现有 · 当前 Scope 不返回</Badge>{/if}
          </span>
          <code class="mt-0.5 block truncate text-micro text-nya-text-tertiary" title={claim}>{claim}</code>
        </label>
        <span class="pt-0.5">
          <FieldHelp
            id={`${idPrefix}-claim-${claim}-help`}
            text={`${CLAIM_HELP[claim]?.description || claim}${available ? '' : ' 此 Claim 属于客户端既有配置，当前 Scope 目录不会返回它；可保留或主动移除。'}`}
            label={`查看 ${claim} Claim 说明`}
          />
        </span>
      </div>
    {/each}
  </div>
</fieldset>
