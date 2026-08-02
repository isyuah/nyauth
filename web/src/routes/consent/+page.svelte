<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { api, type ConsentPermission, type ConsentRequest } from '$lib/api';
  import { brandingStore, sessionStore } from '$lib/stores';
  import AuthorizationActions from '$lib/components/oauth/AuthorizationActions.svelte';
  import AuthorizationBrandHeader from '$lib/components/oauth/AuthorizationBrandHeader.svelte';
  import AuthorizationShell from '$lib/components/oauth/AuthorizationShell.svelte';
  import AuthorizationTechnicalInfo from '$lib/components/oauth/AuthorizationTechnicalInfo.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import OAuthClientLogo from '$lib/components/oauth/OAuthClientLogo.svelte';
  import { Check, CircleCheck, Info, ShieldCheck, TriangleAlert, X, XCircle } from 'lucide-svelte';
  import { CLAIM_HELP, RISK_LABELS } from '$lib/oauth-catalog';

  const deviceResultStorageKey = 'nyauth:device-authorization-result';
  let challenge = $derived($page.url.searchParams.get('challenge') || '');
  let consentData = $state<ConsentRequest | null>(null);
  let error = $state('');
  let action = $state<'accept' | 'deny' | ''>('');
  let grantedOptionalScopes = $state<string[]>([]);

  let requiredPermissions = $derived(consentData?.permissions.filter((permission) => permission.required) || []);
  let optionalPermissions = $derived(consentData?.permissions.filter((permission) => !permission.required) || []);
  let deviceFlow = $derived(consentData?.flow === 'device_authorization');
  let currentUser = $derived($sessionStore.session?.user ?? null);

  function permissionTitle(permission: ConsentPermission): string {
    return permission.display_name || permission.scope;
  }

  function permissionDescription(permission: ConsentPermission): string {
    return permission.description || '使用该应用为此集成定义的权限。';
  }

  function toggleOptionalScope(scope: string, checked: boolean) {
    const selected = new Set(grantedOptionalScopes);
    if (checked) selected.add(scope); else selected.delete(scope);
    grantedOptionalScopes = optionalPermissions.map((permission) => permission.scope).filter((item) => selected.has(item));
  }

  function rememberDeviceResult(approved: boolean) {
    if (!deviceFlow || !consentData) return;
    sessionStorage.setItem(deviceResultStorageKey, JSON.stringify({
      approved,
      client_name: consentData.client_name,
      logo_url: consentData.logo_url,
      permission_count: approved ? requiredPermissions.length + grantedOptionalScopes.length : 0,
    }));
  }

  onMount(async () => {
    if (!challenge) { error = '缺少授权请求'; return; }
    const returnTo = `/consent?challenge=${encodeURIComponent(challenge)}`;
    try {
      const session = await sessionStore.initialize(true);
      if (!session) {
        await goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
        return;
      }
      if (session.must_change_password) {
        await goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
        return;
      }
      consentData = await api.consent.get(challenge);
      grantedOptionalScopes = consentData.permissions
        .filter((permission) => !permission.required && (!consentData?.previously_authorized || permission.previously_granted))
        .map((permission) => permission.scope);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '授权请求无效或已过期';
    }
  });

  async function handleAccept() {
    action = 'accept';
    try {
      const response = await api.consent.accept(challenge, grantedOptionalScopes);
      rememberDeviceResult(true);
      window.location.href = response.redirect_url;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '授权失败';
      action = '';
    }
  }

  async function handleDeny() {
    action = 'deny';
    try {
      const response = await api.consent.deny(challenge);
      rememberDeviceResult(false);
      window.location.href = response.redirect_url;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '操作失败';
      action = '';
    }
  }
</script>

<svelte:head><title>{deviceFlow ? '设备授权' : '授权确认'} - {$brandingStore.title}</title></svelte:head>

<AuthorizationShell label={deviceFlow ? '设备授权' : '授权确认'}>
  {#if error}
    <div class="p-8 text-center">
      <XCircle size={38} class="mx-auto mb-3 text-nya-danger" />
      <h1 class="text-card-title text-nya-text-primary">无法继续授权</h1>
      <p class="mt-2 text-body text-nya-danger">{error}</p>
    </div>
  {:else if !consentData}
    <div class="p-12 text-center text-small text-nya-text-tertiary" role="status">正在加载授权信息…</div>
  {:else}
    <div class="p-6 sm:p-8">
      <AuthorizationBrandHeader />

      <div class="mt-6 flex items-start gap-4 border-b border-nya-divider pb-5">
        <OAuthClientLogo name={consentData.client_name} url={consentData.logo_url} size="lg" />
        <div class="min-w-0 flex-1">
          <h1 class="text-xl font-bold text-nya-text-primary">{consentData.client_name}</h1>
          <p class="mt-1 text-body text-nya-text-secondary">{deviceFlow ? `希望在另一台设备上使用您的 ${$brandingStore.title} 账户` : `希望使用您的 ${$brandingStore.title} 账户`}</p>
          <div class="mt-2 flex flex-wrap gap-2">
            {#if consentData.verification_status === 'verified'}<Badge variant="success">已验证发布者</Badge>
            {:else if consentData.verification_status === 'not_applicable'}<Badge variant="primary">管理员配置应用</Badge>
            {:else}<Badge variant="warning">发布者未验证</Badge>{/if}
            {#if consentData.previously_authorized}<Badge variant="success">之前已授权</Badge>{/if}
          </div>
        </div>
      </div>

      {#if currentUser}
        <div class="my-4 flex min-w-0 items-center gap-3 rounded-nya-md border border-nya-border bg-nya-surface-soft px-3 py-2.5">
          <span class="grid h-9 w-9 shrink-0 place-items-center overflow-hidden rounded-full bg-nya-primary text-small font-bold text-[var(--nya-primary-contrast)]">
            {#if currentUser.avatar_url}<img src={currentUser.avatar_url} alt="" class="h-full w-full object-cover" />{:else}{(currentUser.display_name || currentUser.username).slice(0, 1).toUpperCase()}{/if}
          </span>
          <span class="min-w-0 flex-1"><span class="block text-micro text-nya-text-tertiary">以此账户继续</span><strong class="block truncate text-small text-nya-text-primary">{currentUser.display_name || currentUser.username}</strong></span>
          {#if currentUser.email}<span class="hidden truncate text-small text-nya-text-secondary sm:block">{currentUser.email}</span>{/if}
        </div>
      {/if}

      <div class="mb-4 flex items-start gap-2 rounded-nya-sm px-3 py-2.5 text-small {consentData.verification_status === 'unverified' ? 'bg-nya-warning-soft text-nya-warning' : consentData.verification_status === 'verified' ? 'bg-nya-success-soft text-nya-success' : 'bg-nya-info-soft text-nya-info'}">
        {#if consentData.verification_status === 'unverified'}<TriangleAlert size={16} class="mt-0.5 shrink-0" />
        {:else}<ShieldCheck size={16} class="mt-0.5 shrink-0" />{/if}
        <span>{consentData.verification_status === 'unverified'
          ? `${$brandingStore.title} 尚未验证此应用的发布者，请核对应用身份${deviceFlow ? '和发起请求的设备' : '与回调来源'}。`
          : consentData.verification_status === 'verified'
            ? `此应用已经由 ${$brandingStore.title} 管理员审核，仍请确认本次请求符合预期。`
            : `此应用由 ${$brandingStore.title} 管理员直接配置和管理。`}</span>
      </div>

      {#if consentData.reauthorization_required}
        <div class="mb-4 flex items-start gap-2 rounded-nya-sm border border-nya-danger/25 bg-nya-danger-soft px-3 py-2.5 text-small text-nya-danger" role="alert"><TriangleAlert size={16} class="mt-0.5 shrink-0" /><span>应用的回调地址或授权能力发生了高风险变更。旧授权不再适用，请重新核对。</span></div>
      {:else if consentData.application_changed}
        <div class="mb-4 flex items-start gap-2 rounded-nya-sm bg-nya-warning-soft px-3 py-2.5 text-small text-nya-warning" role="status"><Info size={16} class="mt-0.5 shrink-0" /><span>此应用的名称、Logo、公开链接或发布者状态在上次授权后发生了变化。</span></div>
      {/if}

      <AuthorizationTechnicalInfo consent={consentData} {deviceFlow} />

      {#if requiredPermissions.length > 0}
        <section class="mt-6" aria-labelledby="required-permissions-title">
          <div class="mb-2 flex items-baseline justify-between gap-3"><h2 id="required-permissions-title" class="text-body font-semibold text-nya-text-primary">必需权限</h2><span class="text-micro text-nya-text-tertiary">不同意时只能拒绝整个请求</span></div>
          <div class="divide-y divide-nya-divider border-y border-nya-divider">
            {#each requiredPermissions as permission}
              <div class="flex min-h-[74px] items-center gap-3 px-1 py-3 {permission.risk_level === 'sensitive' ? 'bg-nya-warning-soft/50' : ''}">
                <CircleCheck size={19} class="shrink-0 text-nya-success" />
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-x-2 gap-y-1"><strong class="text-body text-nya-text-primary">{permissionTitle(permission)}</strong><code class="rounded bg-nya-surface-muted px-1.5 py-0.5 text-micro text-nya-text-tertiary">{permission.scope}</code><span class="text-micro text-nya-text-tertiary">{RISK_LABELS[permission.risk_level] || permission.risk_level}</span>{#if permission.newly_requested}<Badge variant="warning">新增请求</Badge>{:else if permission.previously_granted}<Badge variant="success">之前已授权</Badge>{/if}</div>
                  <p class="mt-1 text-small text-nya-text-secondary">{permissionDescription(permission)}</p>
                  {#if permission.claims.length > 0}<p class="mt-1 text-micro text-nya-text-tertiary">包含：{permission.claims.map((claim) => `${CLAIM_HELP[claim]?.title || claim}${consentData?.new_claims.includes(claim) ? '（新增）' : ''}`).join('、')}</p>{/if}
                </div>
              </div>
            {/each}
          </div>
        </section>
      {/if}

      {#if optionalPermissions.length > 0}
        <section class="mt-5" aria-labelledby="optional-permissions-title">
          <h2 id="optional-permissions-title" class="mb-2 text-body font-semibold text-nya-text-primary">可选权限</h2>
          <div class="divide-y divide-nya-divider border-y border-nya-divider">
            {#each optionalPermissions as permission}
              {@const selected = grantedOptionalScopes.includes(permission.scope)}
              <label class="flex min-h-[74px] cursor-pointer items-center gap-3 px-1 py-3 transition-colors hover:bg-nya-surface-soft {permission.risk_level === 'sensitive' ? 'bg-nya-warning-soft/50' : ''}">
                <input class="sr-only" type="checkbox" checked={selected} onchange={(event) => toggleOptionalScope(permission.scope, event.currentTarget.checked)} />
				<span class="pointer-events-none relative h-5 w-5 shrink-0" aria-hidden="true">
                  <Check size={19} class="absolute inset-0 text-nya-success transition duration-normal {selected ? 'scale-100 opacity-100' : 'scale-75 opacity-0'}" />
                  <X size={19} class="absolute inset-0 text-nya-danger transition duration-normal {selected ? 'scale-75 opacity-0' : 'scale-100 opacity-100'}" />
                </span>
                <span class="min-w-0 flex-1">
                  <span class="flex flex-wrap items-center gap-x-2 gap-y-1"><strong class="text-body text-nya-text-primary">{permissionTitle(permission)}</strong><code class="rounded bg-nya-surface-muted px-1.5 py-0.5 text-micro text-nya-text-tertiary">{permission.scope}</code><span class="text-micro text-nya-text-tertiary">{RISK_LABELS[permission.risk_level] || permission.risk_level}</span>{#if permission.newly_requested}<Badge variant="warning">新增请求</Badge>{:else if permission.previously_granted}<Badge variant="success">之前已授权</Badge>{/if}</span>
                  <span class="mt-1 block text-small text-nya-text-secondary">{permissionDescription(permission)}</span>
                  {#if permission.claims.length > 0}<span class="mt-1 block text-micro text-nya-text-tertiary">包含：{permission.claims.map((claim) => `${CLAIM_HELP[claim]?.title || claim}${consentData?.new_claims.includes(claim) ? '（新增）' : ''}`).join('、')}</span>{/if}
                </span>
              </label>
            {/each}
          </div>
          <p class="mt-2 flex items-start gap-1.5 text-micro text-nya-text-tertiary"><Info size={13} class="mt-0.5 shrink-0" />关闭可选权限后，应用收到的 Token Scope 会相应缩减，部分功能可能不可用。</p>
        </section>
      {/if}

      <AuthorizationActions acceptLabel={deviceFlow ? '允许设备访问' : '授权所选权限'} {action} onaccept={handleAccept} ondeny={handleDeny} />
    </div>
  {/if}
</AuthorizationShell>
