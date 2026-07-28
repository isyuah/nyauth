<script lang="ts">
  import { onMount } from 'svelte';
  import { api, isRecentAuthenticationError, type ExternalIdentity, type ProviderSummary, type SessionInfo } from '$lib/api';
  import { consumeProviderAuthError, sessionStore } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import ProviderIcon from '$lib/components/identity/ProviderIcon.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import { CheckCircle, KeyRound, Link2 } from 'lucide-svelte';

  const returnTo = '/profile/identities';
  const initialProviderAuthError = consumeProviderAuthError();
  let session = $derived($sessionStore.session);
  let identities = $state<ExternalIdentity[]>([]);
  let availableProviders = $state<ProviderSummary[]>([]);
  let identitiesLoading = $state(true);
  let identitiesError = $state('');
  let providersLoading = $state(true);
  let providersError = $state('');
  let actionError = $state('');
  let notice = $state(initialProviderAuthError?.message ?? '');
  let bindingProvider = $state('');
  let identityTarget = $state<ExternalIdentity | null>(null);
  let confirmOpen = $state(false);
  let confirmError = $state('');
  let reauthOpen = $state(false);

  function hasRecentAuthentication(value?: string): boolean {
    if (!value) return false;
    const authenticatedAt = Date.parse(value);
    if (!Number.isFinite(authenticatedAt)) return false;
    const age = Date.now() - authenticatedAt;
    return age >= -60_000 && age <= 10 * 60_000;
  }

  function applySession(next: SessionInfo) {
    sessionStore.setSession(next);
  }

  function promptForReauthentication(message = '此操作需要最近 10 分钟内重新验证身份。') {
    actionError = message;
    reauthOpen = true;
  }

  async function loadIdentities() {
    identitiesLoading = true;
    identitiesError = '';
    try {
      identities = await api.getMyIdentities();
    } catch (cause) {
      identitiesError = cause instanceof Error ? cause.message : '外部身份加载失败';
    } finally {
      identitiesLoading = false;
    }
  }

  async function loadProviders() {
    providersLoading = true;
    providersError = '';
    try {
      availableProviders = await api.getProviders();
    } catch (cause) {
      providersError = cause instanceof Error ? cause.message : '身份提供商加载失败';
    } finally {
      providersLoading = false;
    }
  }

  onMount(() => {
    void loadIdentities();
    void loadProviders();
  });

  async function bindProvider(name: string) {
    bindingProvider = name;
    actionError = '';
    try {
      const result = await api.bindIdentity(name, returnTo);
      window.location.assign(result.redirect_url);
    } catch (cause) {
      actionError = cause instanceof Error ? cause.message : '无法发起身份绑定';
      bindingProvider = '';
    }
  }

  function requestIdentityRemoval(identity: ExternalIdentity) {
    if (!hasRecentAuthentication(session?.authenticated_at)) {
      promptForReauthentication();
      return;
    }
    identityTarget = identity;
    confirmError = '';
    confirmOpen = true;
  }

  async function removeIdentity() {
    const target = identityTarget;
    if (!target) return;
    confirmError = '';
    try {
      const next = await api.deleteMyIdentity(target.id);
      applySession(next);
      identities = identities.filter((identity) => identity.id !== target.id);
      identityTarget = null;
      notice = `已解绑 ${target.provider} 身份，当前会话已安全轮换。`;
    } catch (cause) {
      if (isRecentAuthenticationError(cause)) {
        confirmOpen = false;
        promptForReauthentication();
        return;
      }
      confirmError = cause instanceof Error ? cause.message : '无法解绑外部身份';
      throw cause;
    }
  }

  function handleReauthenticated(next: SessionInfo) {
    applySession(next);
    actionError = '';
    notice = '身份验证已刷新，请重新选择要解绑的外部身份。';
  }
</script>

<svelte:head><title>外部身份 - Nya</title></svelte:head>

{#if notice}<div class="mb-4 rounded-nya-sm bg-nya-warning-soft px-4 py-3 text-small text-nya-warning" role="status">{notice}</div>{/if}
{#if actionError}<div class="mb-4 rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">{actionError}</div>{/if}

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="flex items-center justify-between border-b border-nya-divider px-7 py-5">
    <div class="flex items-center gap-2"><KeyRound size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">外部身份</h2></div>
    <Badge variant="default">{identitiesLoading ? '加载中' : `${identities.length} 个已绑定`}</Badge>
  </div>
  <div class="space-y-5 px-7 py-6">
    {#if identitiesLoading}
      <p class="text-body text-nya-text-tertiary" role="status">正在加载外部身份…</p>
    {:else if identitiesError}
      <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger" role="alert">{identitiesError}</p><Button variant="ghost" size="sm" onclick={loadIdentities}>重试</Button></div>
    {:else}
      {#if identities.length > 0}
        <div class="space-y-3">
          {#each identities as identity}
            <div class="flex items-center justify-between gap-4 rounded-nya-sm border border-nya-border p-3.5">
              <div class="flex min-w-0 items-center gap-3">
                <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-nya-surface-muted text-nya-text-primary"><ProviderIcon type={identity.provider_type} iconKey={identity.provider_icon_key} size={18} /></span>
                <div class="min-w-0"><p class="text-body-medium font-semibold text-nya-text-primary">{identity.provider_display_name || identity.provider}</p><p class="truncate text-small text-nya-text-secondary">{identity.external_username || identity.external_id}</p></div>
              </div>
              <div class="flex items-center gap-2"><Badge variant="success">已绑定</Badge><Button variant="ghost" size="sm" requiredCapability="account_mutations" onclick={() => requestIdentityRemoval(identity)}>解绑</Button></div>
            </div>
          {/each}
        </div>
      {:else}
        <p class="rounded-nya-sm bg-nya-surface-muted px-4 py-5 text-center text-body text-nya-text-tertiary">尚未绑定外部身份</p>
      {/if}
    {/if}

    <div>
      <p class="mb-2 text-small font-semibold uppercase tracking-wide text-nya-text-secondary">可绑定的提供商</p>
      {#if providersLoading}
        <p class="text-body text-nya-text-tertiary" role="status">正在加载身份提供商…</p>
      {:else if providersError}
        <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2"><p class="text-small text-nya-danger" role="alert">{providersError}</p><Button variant="ghost" size="sm" onclick={loadProviders}>重试</Button></div>
      {:else if availableProviders.length > 0}
        <div class="flex flex-wrap gap-3">
          {#each availableProviders as provider}
            {@const alreadyBound = identities.some((identity) => identity.provider === provider.name)}
            <Button variant="secondary" requiredCapability="account_mutations" disabled={identitiesLoading || !!identitiesError || alreadyBound} loading={bindingProvider === provider.name} onclick={() => bindProvider(provider.name)}><ProviderIcon type={provider.type} iconKey={provider.icon_key} size={16} />{provider.display_name || provider.name}{#if alreadyBound}<CheckCircle size={14} />{:else}<Link2 size={14} />{/if}</Button>
          {/each}
        </div>
      {:else}
        <p class="text-body text-nya-text-tertiary">当前没有启用的身份提供商。</p>
      {/if}
    </div>
  </div>
</section>

<ConfirmDialog
  bind:open={confirmOpen}
  title="解绑外部身份"
  description={`解绑“${identityTarget?.provider || ''}”后，将无法再使用该身份登录。若这是最后一种登录方式，服务器会拒绝操作。`}
  confirmLabel="确认解绑"
  confirmationText={identityTarget?.provider || ''}
  error={confirmError}
  onconfirm={removeIdentity}
/>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="解绑外部身份前需要验证最近 10 分钟内的身份"
  onauthenticated={handleReauthenticated}
/>
