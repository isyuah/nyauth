<script lang="ts">
  import { api } from '$lib/api';
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { consumeProviderAuthError, sessionStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { KeyRound, Save, Camera, Link2, CheckCircle, Shield, Mail, Calendar } from 'lucide-svelte';

  let me = $state<any>(null);
  let identities = $state<any[]>([]);
  let availableProviders = $state<Array<{name: string; type: string}>>([]);
  let displayName = $state('');
  let avatarUrl = $state('');
  let email = $state('');
  let saving = $state(false);
  let saved = $state(false);
  let error = $state('');
  let loading = $state(true);

  onMount(async () => {
    const providerError = consumeProviderAuthError();
    if (providerError) error = providerError;
    const session = await sessionStore.initialize();
    if (!session) { goto(`/login?return_to=${encodeURIComponent('/profile')}`); return; }
    if (session.must_change_password) { goto('/change-password'); return; }
    try {
      me = await api.getMe();
      displayName = me.display_name || '';
      avatarUrl = me.avatar_url || '';
      email = me.email || '';
      try { identities = (await api.getMyIdentities()) || []; } catch { identities = []; }
      try { availableProviders = (await api.getProviders()) || []; } catch { availableProviders = []; }
    } catch (err) {
      error = err instanceof Error ? err.message : '个人资料加载失败';
    } finally { loading = false; }
  });

  async function handleSave() {
    saving = true; error = ''; saved = false;
    try {
      await api.updateMe({ display_name: displayName || null, avatar_url: avatarUrl || null, email: email || null });
      // Refresh user data
      me = await api.getMe();
      saved = true;
      setTimeout(() => (saved = false), 3000);
    } catch (e) { error = e instanceof Error ? e.message : '保存失败'; }
    finally { saving = false; }
  }

  async function bindProvider(name: string) {
    error = '';
    try {
      const result = await api.bindIdentity(name, '/profile');
      window.location.assign(result.redirect_url);
    } catch (err) {
      error = err instanceof Error ? err.message : '无法发起身份绑定';
    }
  }

  const providerIcons: Record<string, string> = { github: '🐙', google: '🔵', generic: '🔗' };
</script>

<svelte:head><title>个人资料 - Nya</title></svelte:head>

<div class="flex justify-center" style="padding: 20px 16px 48px;">
  <div style="width: 100%; max-width: 720px;">

    <!-- 页面标题 -->
    <div style="margin-bottom: 28px;">
      <h1 style="font-size: 24px; font-weight: 700; color: var(--nya-text-primary); margin: 0;">个人资料</h1>
      <p style="font-size: 14px; color: var(--nya-text-secondary); margin-top: 4px;">管理你的账户信息与外部身份绑定</p>
    </div>

    {#if loading}
      <div class="flex items-center justify-center" style="height: 200px; color: var(--nya-text-tertiary);">
        <div class="animate-spin rounded-full h-6 w-6 border-2 border-[var(--nya-primary)]/30 border-t-[var(--nya-primary)]"></div>
      </div>
    {:else if me}
      <!-- 头像卡片 -->
      <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)] overflow-hidden" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card); margin-bottom: 20px;">
        <!-- 顶部装饰条 -->
        <div style="height: 80px; background: linear-gradient(135deg, #f1edff 0%, #fff0f6 50%, #edf8ff 100%);"></div>
        <div style="padding: 0 28px 24px;">
          <!-- 头像 -->
          <div class="flex items-end gap-5" style="margin-top: -36px;">
            <div class="shrink-0 relative group" style="width: 88px; height: 88px;">
              <div class="w-full h-full rounded-full border-4 border-[var(--nya-surface)] flex items-center justify-center overflow-hidden" style="background: linear-gradient(135deg, #f1edff, #fff0f6);">
                {#if me.avatar_url}
                  <img src={me.avatar_url} alt="avatar" style="width: 100%; height: 100%; object-fit: cover;" />
                {:else}
                  <span style="font-size: 32px; font-weight: 700; color: var(--nya-primary);">{(me.username || '?')[0].toUpperCase()}</span>
                {/if}
              </div>
              <div class="absolute inset-0 rounded-full flex items-center justify-center bg-black/30 opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer" title="在下方修改头像 URL">
                <Camera size={20} color="#fff" />
              </div>
            </div>
            <div class="flex-1 pb-1">
              <h2 style="font-size: 20px; font-weight: 700; color: var(--nya-text-primary); margin: 0; line-height: 1.2;">
                {me.display_name || me.username}
              </h2>
              <p style="font-size: 13px; color: var(--nya-text-secondary); margin-top: 2px;">@{me.username}</p>
            </div>
            <div class="pb-1">
              <Badge variant={me.role === 'admin' ? 'pink' : 'primary'}>{me.role === 'admin' ? '管理员' : '用户'}</Badge>
            </div>
          </div>

          <!-- 元信息 -->
          <div class="flex flex-wrap gap-4 mt-4" style="font-size: 12px; color: var(--nya-text-tertiary);">
            <span class="flex items-center gap-1"><Mail size={13} /> {me.email || '未设置邮箱'}</span>
            <span class="flex items-center gap-1"><Calendar size={13} /> 注册于 {new Date(me.created_at).toLocaleDateString()}</span>
            {#if me.last_login_at}
              <span class="flex items-center gap-1"><Shield size={13} /> 最后登录 {new Date(me.last_login_at).toLocaleString()}</span>
            {/if}
          </div>
        </div>
      </div>

      <!-- 编辑资料 -->
      <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card); margin-bottom: 20px;">
        <div style="padding: 20px 28px; border-bottom: 1px solid var(--nya-divider);">
          <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary); margin: 0;">编辑资料</h3>
        </div>
        <div style="padding: 24px 28px;">
          {#if error}
            <div class="mb-4 px-4 py-3 rounded-lg" style="background: var(--nya-danger-soft); font-size: 13px; color: var(--nya-danger);">{error}</div>
          {/if}
          {#if saved}
            <div class="mb-4 flex items-center gap-2 px-4 py-3 rounded-lg" style="background: var(--nya-success-soft); font-size: 13px; color: var(--nya-success);">
              <CheckCircle size={16} /> 保存成功
            </div>
          {/if}
          <div class="space-y-5">
            <Input label="显示名称" bind:value={displayName} placeholder="给自己取个名字" />
            <Input label="邮箱地址" type="email" bind:value={email} placeholder="your@email.com" />
            <Input label="头像 URL" bind:value={avatarUrl} placeholder="https://example.com/avatar.png" />
            <p style="font-size: 12px; color: var(--nya-text-tertiary); margin-top: -12px;">
              填入图片链接，保存后头像会立即更新
            </p>
            <div class="flex justify-end" style="padding-top: 4px;">
              <Button variant="primary" onclick={handleSave} loading={saving}>
                <Save size={16} /> 保存更改
              </Button>
            </div>
          </div>
        </div>
      </div>

      <!-- 安全设置 -->
      <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card); margin-bottom: 20px;">
        <div class="flex items-center justify-between gap-4" style="padding: 20px 28px;">
          <div>
            <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary); margin: 0;">账户安全</h3>
            <p style="font-size: 13px; color: var(--nya-text-secondary); margin-top: 4px;">修改密码会退出其他设备并撤销已有令牌。</p>
          </div>
          <Button variant="secondary" onclick={() => goto('/change-password?return_to=/profile')}>
            <KeyRound size={16} /> 修改密码
          </Button>
        </div>
      </div>

      <!-- 外部身份绑定 -->
      <div class="bg-[var(--nya-surface)] border border-[var(--nya-border)]" style="border-radius: var(--nya-radius-card); box-shadow: var(--nya-shadow-card);">
        <div style="padding: 20px 28px; border-bottom: 1px solid var(--nya-divider);">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <KeyRound size={18} style="color: var(--nya-primary);" />
              <h3 style="font-size: 16px; font-weight: 650; color: var(--nya-text-primary); margin: 0;">外部身份绑定</h3>
            </div>
            <Badge variant="default">{identities.length} 个已绑定</Badge>
          </div>
        </div>
        <div style="padding: 24px 28px;">
          <!-- 已绑定 -->
          {#if identities.length > 0}
            <div class="space-y-3" style="margin-bottom: 20px;">
              {#each identities as ident}
                <div class="flex items-center justify-between p-3.5 rounded-lg border border-[var(--nya-border)]" style="background: var(--nya-surface);">
                  <div class="flex items-center gap-3">
                    <div class="flex items-center justify-center rounded-full" style="width: 36px; height: 36px; background: var(--nya-surface-muted); font-size: 18px;">
                      {providerIcons[ident.provider] || '🔗'}
                    </div>
                    <div>
                      <p style="font-size: 14px; font-weight: 550; color: var(--nya-text-primary);">{ident.provider}</p>
                      <p style="font-size: 12px; color: var(--nya-text-secondary);">{ident.external_username || ident.external_id}</p>
                    </div>
                  </div>
                  <div class="flex items-center gap-2">
                    <Badge variant="success">已绑定</Badge>
                    {#if ident.external_email}
                      <span style="font-size: 12px; color: var(--nya-text-tertiary);">{ident.external_email}</span>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {:else}
            <p style="font-size: 13px; color: var(--nya-text-tertiary); text-align: center; padding: 20px 0; margin-bottom: 16px;">
              还没有绑定外部身份提供商
            </p>
          {/if}

          <!-- 可绑定的 Provider -->
          {#if availableProviders.length > 0}
            <div>
              <p style="font-size: 12px; font-weight: 600; color: var(--nya-text-secondary); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.05em;">可绑定的提供商</p>
              <div class="flex flex-wrap gap-3">
                {#each availableProviders as p}
                  {@const alreadyBound = identities.some(i => i.provider === p.name)}
                  <button
                    onclick={() => !alreadyBound && bindProvider(p.name)}
                    disabled={alreadyBound}
                    class="flex items-center gap-2.5 px-4 py-2.5 rounded-lg border transition-all"
                    style="background: {alreadyBound ? 'var(--nya-surface-muted)' : 'var(--nya-surface)'}; border-color: {alreadyBound ? 'var(--nya-divider)' : 'var(--nya-border)'}; cursor: {alreadyBound ? 'default' : 'pointer'}; opacity: {alreadyBound ? 0.6 : 1};"
                  >
                    <span style="font-size: 18px;">{providerIcons[p.type] || '🔗'}</span>
                    <span style="font-size: 13px; font-weight: 550; color: var(--nya-text-primary);">{p.name}</span>
                    {#if alreadyBound}
                      <CheckCircle size={14} style="color: var(--nya-success);" />
                    {:else}
                      <Link2 size={14} style="color: var(--nya-primary);" />
                    {/if}
                  </button>
                {/each}
              </div>
            </div>
          {/if}
        </div>
      </div>
    {/if}
  </div>
</div>
