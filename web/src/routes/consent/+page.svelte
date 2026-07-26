<script lang="ts">
  import { page } from '$app/stores';
  import { api, type ConsentRequest } from '$lib/api';
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Card from '$lib/components/ui/Card.svelte';
  import { Shield, CheckCircle, XCircle, TriangleAlert } from 'lucide-svelte';

  let challenge = $derived($page.url.searchParams.get('challenge') || '');
  let consentData = $state<ConsentRequest | null>(null);
  let error = $state('');
  let action = $state<'accept' | 'deny' | ''>('');

  const scopeDescriptions: Record<string, string> = {
    openid: '确认你的身份并签发 ID Token',
    profile: '读取用户名、显示名称和头像',
    email: '读取你的邮箱地址及验证状态',
    offline_access: '在你离开后继续访问，并获得可轮换的 Refresh Token',
  };

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
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '授权请求无效或已过期';
    }
  });

  async function handleAccept() {
    action = 'accept';
    try {
      const res = await api.consent.accept(challenge);
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

          <div class="border-y border-nya-border py-3">
            <dl class="space-y-2 text-small">
              <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">Client ID</dt><dd class="break-all font-mono text-nya-text-primary">{consentData.client_id}</dd></div>
              <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">注册来源</dt><dd class="text-nya-text-primary">{consentData.publisher_type === 'system_managed' ? '系统管理员配置' : '用户注册应用'}</dd></div>
              <div class="grid grid-cols-[88px_1fr] gap-3"><dt class="text-nya-text-tertiary">回调来源</dt><dd class="break-all font-mono text-nya-text-primary">{consentData.redirect_origin || '不可用'}</dd></div>
            </dl>
            <div class="mt-3 flex items-start gap-2 rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning" role="status">
              <TriangleAlert size={15} class="mt-0.5 shrink-0" />
              <span>Nyauth 尚未验证此应用的发布者，请仅在确认应用身份和回调来源后授权。</span>
            </div>
          </div>

          <div>
            <p class="text-small text-nya-text-tertiary mb-2">该应用将获得以下权限：</p>
            <div class="space-y-2">
              {#each consentData.scopes as scope}
                <div class="flex items-start gap-2.5 px-3 py-2 bg-nya-surface-soft rounded-nya-sm {scope === 'offline_access' ? 'border border-nya-warning/30 bg-nya-warning-soft' : ''}">
                  <CheckCircle size={14} class="text-nya-success shrink-0" />
                  <span><span class="block text-body text-nya-text-primary font-mono">{scope}</span><span class="block text-small text-nya-text-secondary">{scopeDescriptions[scope] || '访问该应用请求的对应账户信息'}</span></span>
                </div>
              {/each}
            </div>
          </div>

          <div class="flex gap-3 pt-2">
            <Button variant="secondary" size="md" onclick={handleDeny} loading={action === 'deny'} disabled={action !== ''}>拒绝</Button>
            <Button variant="primary" size="md" onclick={handleAccept} loading={action === 'accept'} disabled={action !== ''}>授权</Button>
          </div>
        </div>
      </Card>
    {/if}
  </div>
</div>
