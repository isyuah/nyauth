<script lang="ts">
  import { api, type ExternalIdentity } from '$lib/api';
  import { sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import { ExternalLink, KeyRound } from 'lucide-svelte';

  interface Props {
    open: boolean;
    returnTo: string;
    description?: string;
    onauthenticated: () => void | Promise<void>;
    onbeforeprovider?: () => void;
  }

  let {
    open = $bindable(false),
    returnTo,
    description = '完成后，当前敏感操作将在 10 分钟内可用',
    onauthenticated,
    onbeforeprovider,
  }: Props = $props();

  let password = $state('');
  let passwordLoading = $state(false);
  let providerLoading = $state('');
  let identities = $state<ExternalIdentity[]>([]);
  let identitiesLoading = $state(false);
  let loadedForOpen = $state(false);
  let error = $state('');

  let hasPassword = $derived($sessionStore.session?.has_password ?? false);
  let providers = $derived(Array.from(new Set(identities.map((identity) => identity.provider))));

  $effect(() => {
    if (open && !loadedForOpen) {
      loadedForOpen = true;
      password = '';
      error = '';
      void loadIdentities();
    }
    if (!open) loadedForOpen = false;
  });

  async function loadIdentities() {
    identitiesLoading = true;
    try {
      identities = await api.getMyIdentities();
    } catch (cause) {
      identities = [];
      error = cause instanceof Error ? cause.message : '重新认证方式加载失败';
    } finally {
      identitiesLoading = false;
    }
  }

  async function submitPassword(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    passwordLoading = true;
    try {
      const updated = await api.reauthenticateWithPassword(password);
      sessionStore.setSession(updated);
      password = '';
      open = false;
      await onauthenticated();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '重新认证失败';
    } finally {
      passwordLoading = false;
    }
  }

  async function beginProvider(provider: string) {
    error = '';
    providerLoading = provider;
    try {
      const result = await api.reauthenticateWithProvider(provider, returnTo);
      onbeforeprovider?.();
      window.location.assign(result.redirect_url);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法发起外部身份重新认证';
      providerLoading = '';
    }
  }
</script>

<Modal bind:open title="重新验证身份" {description} size="sm">
  <div class="space-y-4">
    {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
    {#if hasPassword}
      <form onsubmit={submitPassword} class="space-y-3">
        <Input id="sensitive-action-password" label="当前密码" type="password" bind:value={password} autocomplete="current-password" required />
        <Button type="submit" variant="primary" loading={passwordLoading} fullWidth><KeyRound size={16} /> 使用密码验证</Button>
      </form>
    {/if}
    {#if identitiesLoading}
      <p class="text-center text-small text-nya-text-tertiary" role="status">正在加载外部认证方式…</p>
    {:else if providers.length > 0}
      <div class="space-y-2">
        {#each providers as provider}
          <Button variant="secondary" loading={providerLoading === provider} disabled={passwordLoading || (providerLoading !== '' && providerLoading !== provider)} fullWidth onclick={() => beginProvider(provider)}>
            <ExternalLink size={16} /> 使用 {provider} 验证
          </Button>
        {/each}
      </div>
    {:else if !hasPassword && !error}
      <p class="rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">当前账户没有可用的重新认证方式，请联系管理员。</p>
    {/if}
    <div class="flex justify-end"><Button variant="ghost" onclick={() => (open = false)} disabled={passwordLoading || providerLoading !== ''}>取消</Button></div>
  </div>
</Modal>
