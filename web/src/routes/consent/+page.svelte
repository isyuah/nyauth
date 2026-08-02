<script lang="ts">
  import { page } from '$app/stores';
  import { api, type ConsentPermission, type ConsentRequest } from '$lib/api';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import OAuthClientLogo from '$lib/components/oauth/OAuthClientLogo.svelte';
  import { Shield, CheckCircle, ExternalLink, XCircle, TriangleAlert, Info } from 'lucide-svelte';
  import { CLAIM_HELP, RISK_LABELS } from '$lib/oauth-catalog';

  let challenge = $derived($page.url.searchParams.get('challenge') || '');
  let consentData = $state<ConsentRequest | null>(null);
  let error = $state('');
  let action = $state<'accept' | 'deny' | ''>('');
  let grantedOptionalScopes = $state<string[]>([]);

  let requiredPermissions = $derived(consentData?.permissions.filter((permission) => permission.required) || []);
  let optionalPermissions = $derived(consentData?.permissions.filter((permission) => !permission.required) || []);
  let deviceFlow = $derived(consentData?.flow === 'device_authorization');

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

  onMount(async () => {
    if (!challenge) { error = '缺少授权请求'; return; }
    const returnTo = `/consent?challenge=${encodeURIComponent(challenge)}`;
    try {
      const session = await sessionStore.initialize(true);
      if (!session) {
        goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
        return;
      }
      if (session.must_change_password) {
        goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
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
      const res = await api.consent.accept(challenge, grantedOptionalScopes);
      window.location.href = res.redirect_url;
    } catch (cause) { error = cause instanceof Error ? cause.message : '授权失败'; action = ''; }
  }

  async function handleDeny() {
    action = 'deny';
    try {
      const res = await api.consent.deny(challenge);
      window.location.href = res.redirect_url;
    } catch (cause) { error = cause instanceof Error ? cause.message : '操作失败'; action = ''; }
  }
</script>

<svelte:head><title>{deviceFlow ? '设备授权' : '授权确认'} - Nya</title></svelte:head>

<div class="min-h-screen flex items-center justify-center px-4 bg-nya-page">
  <div class="w-full max-w-[440px]">
    <div class="text-center mb-6">
      <div class="inline-flex items-center justify-center w-12 h-12 rounded-nya-lg bg-nya-primary-soft mb-3">
        <Shield size={24} class="text-nya-primary" />
      </div>
      <h1 class="text-section-title text-nya-text-primary">{deviceFlow ? '设备授权' : '授权确认'}</h1>
    </div>

    {#if error}
      <Card>
        <div class="text-center py-4">
          <XCircle size={32} class="text-nya-danger mx-auto mb-2" />
          <p class="text-body text-nya-danger">{error}</p>
        </div>
      </Card>
    {:else if !consentData}
      <Card><div class="text-center py-8 text-nya-text-tertiary">加载中...</div></Card>
    {:else}
      <Card>
        <div class="space-y-5">
          <div class="flex flex-col items-center text-center">
            <OAuthClientLogo name={consentData.client_name} url={consentData.logo_url} size="lg" />
            <p class="mt-3 text-body text-nya-text-secondary"><strong class="text-nya-text-primary">{consentData.client_name}</strong> {deviceFlow ? '请求在另一台设备上访问您的账户' : '请求访问您的账户'}</p>
            {#if consentData.previously_authorized}<p class="mt-1 text-micro text-nya-text-tertiary">您之前已授权过此应用，请检查本次变化。</p>{/if}
          </div>

          <div class="border-y border-nya-border py-3">
            <dl class="space-y-2 text-small">
              <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">Client ID</dt><dd class="break-all font-mono text-nya-text-primary">{consentData.client_id}</dd></div>
              <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">注册来源</dt><dd class="text-nya-text-primary">{consentData.publisher_type === 'system_managed' ? '系统管理员配置' : '用户注册应用'}</dd></div>
              <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">发布者状态</dt><dd class="text-nya-text-primary">{consentData.verification_status === 'verified' ? '已由管理员审核' : consentData.verification_status === 'not_applicable' ? '系统管理' : '尚未验证'}</dd></div>
              {#if deviceFlow}
                <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">授权方式</dt><dd class="text-nya-text-primary">设备代码授权，不会跳转到第三方回调地址</dd></div>
              {:else}
                <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">回调来源</dt><dd class="break-all font-mono text-nya-text-primary">{consentData.redirect_origin || '不可用'}</dd></div>
              {/if}
            </dl>
            {#if consentData.homepage_uri || consentData.privacy_policy_uri || consentData.terms_of_service_uri}
              <nav aria-label="应用信息链接" class="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-small">
                {#if consentData.homepage_uri}<a href={consentData.homepage_uri} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-nya-primary hover:underline"><ExternalLink size={13} /> 应用主页</a>{/if}
                {#if consentData.privacy_policy_uri}<a href={consentData.privacy_policy_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">隐私政策</a>{/if}
                {#if consentData.terms_of_service_uri}<a href={consentData.terms_of_service_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">服务条款</a>{/if}
              </nav>
            {/if}
            {#if consentData.reauthorization_required}
              <div class="mt-3 flex items-start gap-2 rounded-nya-sm border border-nya-danger/25 bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><TriangleAlert size={15} class="mt-0.5 shrink-0" /><span>应用的回调地址或授权能力已发生高风险变更。旧授权不再适用，请重新核对后授权。</span></div>
            {:else if consentData.application_changed}
              <div class="mt-3 flex items-start gap-2 rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning" role="status"><Info size={15} class="mt-0.5 shrink-0" /><span>此应用的名称、Logo、公开链接或发布者状态在上次授权后已变更。</span></div>
            {/if}
            {#if consentData.verification_status === 'unverified'}
              <div class="mt-3 flex items-start gap-2 rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning" role="status">
                <TriangleAlert size={15} class="mt-0.5 shrink-0" />
                <span>Nyauth 尚未验证此应用的发布者，请仅在确认应用身份{deviceFlow ? '以及发起请求的设备' : '和回调来源'}后授权。</span>
              </div>
            {:else if consentData.verification_status === 'verified'}
              <div class="mt-3 flex items-start gap-2 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">
                <CheckCircle size={15} class="mt-0.5 shrink-0" />
                <span>此用户注册应用已经由 Nyauth 管理员审核；仍请确认{deviceFlow ? '正在授权的是您刚才使用的设备' : '回调来源属于预期应用'}。</span>
              </div>
            {:else}
              <div class="mt-3 flex items-start gap-2 rounded-nya-sm bg-nya-info-soft px-3 py-2 text-small text-nya-info" role="status">
                <Shield size={15} class="mt-0.5 shrink-0" />
                <span>此应用由 Nyauth 管理员直接配置和管理。</span>
              </div>
            {/if}
          </div>

          {#if requiredPermissions.length > 0}
            <section aria-labelledby="required-permissions-title">
              <div class="mb-2 flex items-center justify-between gap-3">
                <p id="required-permissions-title" class="text-small font-semibold text-nya-text-primary">必需权限</p>
                <span class="text-micro text-nya-text-tertiary">若不同意，只能拒绝整个请求</span>
              </div>
              <div class="space-y-2">
                {#each requiredPermissions as permission}
                  <div class="flex items-start gap-2.5 rounded-nya-sm bg-nya-surface-soft px-3 py-2 {permission.scope === 'offline_access' ? 'border border-nya-warning/30 bg-nya-warning-soft' : ''}">
                    <CheckCircle size={15} class="mt-0.5 shrink-0 text-nya-success" />
                    <div class="min-w-0">
                      <div class="flex flex-wrap items-center gap-x-2"><span class="text-body-medium font-semibold text-nya-text-primary">{permissionTitle(permission)}</span><code class="text-micro text-nya-text-tertiary">{permission.scope}</code><span class="text-micro text-nya-text-tertiary">{RISK_LABELS[permission.risk_level] || permission.risk_level}</span>{#if permission.newly_requested}<Badge variant="warning">新增请求</Badge>{:else if permission.previously_granted}<Badge variant="success">之前已授权</Badge>{/if}</div>
                      <p class="text-small text-nya-text-secondary">{permissionDescription(permission)}</p>
                      {#if permission.claims.length > 0}<div class="mt-1 flex flex-wrap gap-1 text-micro text-nya-text-tertiary"><span>包含：</span>{#each permission.claims as claim}<span class={consentData.new_claims.includes(claim) ? 'font-semibold text-nya-warning' : ''}>{CLAIM_HELP[claim]?.title || claim}{consentData.new_claims.includes(claim) ? '（新增）' : ''}</span>{/each}</div>{/if}
                    </div>
                  </div>
                {/each}
              </div>
            </section>
          {/if}

          {#if optionalPermissions.length > 0}
            <section aria-labelledby="optional-permissions-title">
              <div class="mb-2 flex items-center justify-between gap-3">
                <p id="optional-permissions-title" class="text-small font-semibold text-nya-text-primary">可选权限</p>
                <span class="text-micro text-nya-text-tertiary">可逐项关闭</span>
              </div>
              <div class="space-y-2">
                {#each optionalPermissions as permission}
                  <label class="flex cursor-pointer items-start gap-2.5 rounded-nya-sm border border-nya-border px-3 py-2 transition-colors hover:border-nya-primary/50 {permission.scope === 'offline_access' ? 'border-nya-warning/30 bg-nya-warning-soft' : 'bg-nya-surface'}">
                    <input type="checkbox" class="mt-1 shrink-0 rounded" checked={grantedOptionalScopes.includes(permission.scope)} onchange={(event) => toggleOptionalScope(permission.scope, event.currentTarget.checked)} />
                    <span class="min-w-0">
                      <span class="flex flex-wrap items-center gap-x-2"><span class="text-body-medium font-semibold text-nya-text-primary">{permissionTitle(permission)}</span><code class="text-micro text-nya-text-tertiary">{permission.scope}</code><span class="text-micro text-nya-text-tertiary">{RISK_LABELS[permission.risk_level] || permission.risk_level}</span>{#if permission.newly_requested}<Badge variant="warning">新增请求</Badge>{:else if permission.previously_granted}<Badge variant="success">之前已授权</Badge>{/if}</span>
                      <span class="block text-small text-nya-text-secondary">{permissionDescription(permission)}</span>
                      {#if permission.claims.length > 0}<span class="mt-1 block text-micro text-nya-text-tertiary">包含：{permission.claims.map((claim) => `${CLAIM_HELP[claim]?.title || claim}${consentData?.new_claims.includes(claim) ? '（新增）' : ''}`).join('、')}</span>{/if}
                    </span>
                  </label>
                {/each}
              </div>
              <div class="mt-2 flex items-start gap-2 text-micro text-nya-text-tertiary"><Info size={13} class="mt-0.5 shrink-0" /><span>关闭可选权限后，应用收到的 Token Scope 会相应缩减，部分应用功能可能不可用。</span></div>
            </section>
          {/if}

          <div class="flex gap-3 pt-2">
            <Button variant="secondary" size="md" onclick={handleDeny} loading={action === 'deny'} disabled={action !== ''}>拒绝</Button>
            <Button variant="primary" size="md" requiredCapability="auth_issuance" onclick={handleAccept} loading={action === 'accept'} disabled={action !== ''}>{deviceFlow ? '允许设备访问' : '授权所选权限'}</Button>
          </div>
        </div>
      </Card>
    {/if}
  </div>
</div>
