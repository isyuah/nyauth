<script lang="ts">
  import { page } from '$app/stores';
  import { api } from '$lib/api';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { Shield, CheckCircle, XCircle } from 'lucide-svelte';

  let challenge = $derived($page.url.searchParams.get('challenge') || '');
  let consentData = $state<any>(null);
  let error = $state('');
  let loading = $state(false);

  onMount(async () => {
    if (!challenge) { error = '缺少授权请求'; return; }
    const returnTo = `/consent?challenge=${encodeURIComponent(challenge)}`;
    const session = await sessionStore.initialize();
    if (!session) {
      goto(`/login?return_to=${encodeURIComponent(returnTo)}`);
      return;
    }
    if (session.must_change_password) {
      goto(`/change-password?return_to=${encodeURIComponent(returnTo)}`);
      return;
    }
    try { consentData = await api.consent.get(challenge); } catch (e) { error = '授权请求无效或已过期'; }
  });

  async function handleAccept() {
    loading = true;
    try {
      const res = await api.consent.accept(challenge);
      window.location.href = res.redirect_url;
    } catch (e) { error = '授权失败'; loading = false; }
  }

  async function handleDeny() {
    loading = true;
    try {
      const res = await api.consent.deny(challenge);
      window.location.href = res.redirect_url;
    } catch (e) { error = '操作失败'; loading = false; }
  }
</script>

<svelte:head><title>授权确认 - Nya</title></svelte:head>

<div class="min-h-screen flex items-center justify-center px-4 bg-nya-page">
  <div class="w-full max-w-[440px]">
    <div class="text-center mb-6">
      <div class="inline-flex items-center justify-center w-12 h-12 rounded-nya-lg bg-nya-primary-soft mb-3">
        <Shield size={24} class="text-nya-primary" />
      </div>
      <h1 class="text-section-title text-nya-text-primary">授权确认</h1>
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
          <div class="text-center">
            <p class="text-body text-nya-text-secondary">
              <strong class="text-nya-text-primary">{consentData.client_name}</strong> 请求访问您的账户
            </p>
          </div>

          <div>
            <p class="text-small text-nya-text-tertiary mb-2">该应用将获得以下权限：</p>
            <div class="space-y-2">
              {#each consentData.scopes as scope}
                <div class="flex items-center gap-2.5 px-3 py-2 bg-nya-surface-soft rounded-nya-sm">
                  <CheckCircle size={14} class="text-nya-success shrink-0" />
                  <span class="text-body text-nya-text-primary font-mono">{scope}</span>
                </div>
              {/each}
            </div>
          </div>

          <div class="flex gap-3 pt-2">
            <Button variant="secondary" size="md" onclick={handleDeny} {loading}>拒绝</Button>
            <Button variant="primary" size="md" onclick={handleAccept} {loading}>授权</Button>
          </div>
        </div>
      </Card>
    {/if}
  </div>
</div>
