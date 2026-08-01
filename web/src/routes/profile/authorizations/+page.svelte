<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type OAuthAuthorization } from '$lib/api';
  import OAuthClientLogo from '$lib/components/oauth/OAuthClientLogo.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import { ExternalLink, Info, TriangleAlert } from 'lucide-svelte';
  import { CLAIM_HELP } from '$lib/oauth-catalog';

  let authorizations = $state<OAuthAuthorization[]>([]);
  let loading = $state(true);
  let error = $state('');
  let target = $state<OAuthAuthorization | null>(null);
  let confirmOpen = $state(false);
  let actionError = $state('');

  async function loadAuthorizations() {
    loading = true;
    error = '';
    try { authorizations = await api.getMyAuthorizations(); }
    catch (cause) { error = cause instanceof Error ? cause.message : 'OAuth 授权加载失败'; }
    finally { loading = false; }
  }

  function requestRevocation(authorization: OAuthAuthorization) {
    target = authorization;
    actionError = '';
    confirmOpen = true;
  }

  async function revokeAuthorization() {
    if (!target) return;
    const authorization = target;
    actionError = '';
    try {
      await api.revokeMyAuthorization(authorization.client_id);
      authorizations = authorizations.filter((item) => item.client_id !== authorization.client_id);
      target = null;
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法撤销 OAuth 授权';
      throw cause;
    }
  }

  onMount(loadAuthorizations);
</script>

<svelte:head><title>OAuth 应用授权 - Nya</title></svelte:head>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="border-b border-nya-divider px-7 py-5">
    <h2 class="text-card-title text-nya-text-primary">OAuth 应用授权</h2>
    <p class="mt-1 text-body text-nya-text-secondary">查看应用当前身份、已授予的权限和最近使用情况。</p>
  </div>
  <div class="px-7 py-6">
    {#if loading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载应用授权…</p>
    {:else if error}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger">{error}</p><Button variant="ghost" size="sm" onclick={loadAuthorizations}>重试</Button></div>
    {:else if authorizations.length === 0}
      <p class="text-body text-nya-text-tertiary">当前没有活动的 OAuth 应用授权。</p>
    {:else}
      <div class="space-y-4">
        {#each authorizations as authorization (authorization.id)}
          <article class="rounded-nya-md border border-nya-border p-5">
            <div class="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
              <div class="flex min-w-0 items-center gap-3">
                <OAuthClientLogo name={authorization.client_name} url={authorization.logo_url} />
                <div class="min-w-0"><h3 class="truncate text-body-medium font-semibold text-nya-text-primary">{authorization.client_name}</h3><code class="block truncate text-micro text-nya-text-tertiary" title={authorization.client_id}>{authorization.client_id}</code></div>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                {#if authorization.reauthorization_required}<Badge variant="danger">需重新授权</Badge>{:else if authorization.application_changed}<Badge variant="warning">应用信息已变更</Badge>{:else}<Badge variant="success">授权有效</Badge>{/if}
                <Button variant="ghost" size="sm" onclick={() => requestRevocation(authorization)}>撤销授权</Button>
              </div>
            </div>

            {#if authorization.reauthorization_required}
              <div class="mt-4 flex items-start gap-2 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger"><TriangleAlert size={15} class="mt-0.5 shrink-0" /><span>应用的回调地址或授权能力发生了高风险变更。此记录不再能继续签发新 Token，下次使用应用时需重新授权。</span></div>
            {:else if authorization.application_changed}
              <div class="mt-4 flex items-start gap-2 rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning"><Info size={15} class="mt-0.5 shrink-0" /><span>应用名称、Logo、公开链接或发布者状态在授权后发生了变化，当前授权仍然有效。</span></div>
            {/if}

            <dl class="mt-4 grid gap-3 text-small sm:grid-cols-2">
              <div><dt class="text-nya-text-tertiary">授权时间</dt><dd class="mt-0.5 text-nya-text-primary">{new Date(authorization.granted_at).toLocaleString()}</dd></div>
              <div><dt class="text-nya-text-tertiary">最近使用</dt><dd class="mt-0.5 text-nya-text-primary">{authorization.last_used_at ? new Date(authorization.last_used_at).toLocaleString() : '尚无使用记录'}</dd></div>
            </dl>

            {#if authorization.application_changed}
              <details class="mt-4 rounded-nya-sm bg-nya-surface-soft px-3 py-2">
                <summary class="cursor-pointer text-small font-semibold text-nya-text-primary">查看授权时的应用信息</summary>
                <dl class="mt-2 space-y-1 text-small text-nya-text-secondary">
                  <div><dt class="inline text-nya-text-tertiary">应用名称：</dt><dd class="inline">{authorization.client_name_at_grant || authorization.client_name}</dd></div>
                  {#if authorization.homepage_uri_at_grant}<div><dt class="inline text-nya-text-tertiary">主页：</dt><dd class="inline break-all">{authorization.homepage_uri_at_grant}</dd></div>{/if}
                  {#if authorization.privacy_policy_uri_at_grant}<div><dt class="inline text-nya-text-tertiary">隐私政策：</dt><dd class="inline break-all">{authorization.privacy_policy_uri_at_grant}</dd></div>{/if}
                  {#if authorization.terms_of_service_uri_at_grant}<div><dt class="inline text-nya-text-tertiary">服务条款：</dt><dd class="inline break-all">{authorization.terms_of_service_uri_at_grant}</dd></div>{/if}
                </dl>
              </details>
            {/if}

            {#if authorization.homepage_uri || authorization.privacy_policy_uri || authorization.terms_of_service_uri}
              <nav aria-label={`${authorization.client_name} 应用信息`} class="mt-4 flex flex-wrap gap-x-4 gap-y-2 text-small">
                {#if authorization.homepage_uri}<a href={authorization.homepage_uri} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-nya-primary hover:underline"><ExternalLink size={13} /> 应用主页</a>{/if}
                {#if authorization.privacy_policy_uri}<a href={authorization.privacy_policy_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">隐私政策</a>{/if}
                {#if authorization.terms_of_service_uri}<a href={authorization.terms_of_service_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">服务条款</a>{/if}
              </nav>
            {/if}

            <div class="mt-4"><p class="mb-2 text-small font-semibold text-nya-text-primary">已授予 Scope</p><div class="flex flex-wrap gap-1.5">{#each authorization.scopes as scope}<Badge variant={scope === 'offline_access' ? 'warning' : 'default'}>{scope}</Badge>{/each}</div></div>
            {#if authorization.allowed_claims.length > 0}<div class="mt-4"><p class="mb-2 text-small font-semibold text-nya-text-primary">允许返回的 Claim</p><div class="flex flex-wrap gap-1.5">{#each authorization.allowed_claims as claim}<Badge variant="info">{CLAIM_HELP[claim]?.title || claim} <code class="ml-1">{claim}</code></Badge>{/each}</div></div>{/if}
          </article>
        {/each}
      </div>
    {/if}
  </div>
</section>

<ConfirmDialog bind:open={confirmOpen} title="撤销 OAuth 应用授权" description={`撤销后，“${target?.client_name || ''}”现有的访问令牌和刷新令牌将失效；再次使用时需要重新授权。`} confirmLabel="撤销授权" error={actionError} onconfirm={revokeAuthorization} />
