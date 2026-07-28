<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type AdminUserSecurity } from '$lib/api';
  import { useAdminUserDetailContext } from '$lib/admin-user-detail';
  import { PASSWORD_REQUIREMENT, passwordPolicyError } from '$lib/password-policy';
  import Badge from '$lib/components/ui/Badge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { KeyRound, ShieldCheck } from 'lucide-svelte';

  const detail = useAdminUserDetailContext();
  let security = $state<AdminUserSecurity | null>(null);
  let loading = $state(true);
  let error = $state('');
  let password = $state('');
  let confirmation = $state('');
  let resetting = $state(false);
  let resetError = $state('');
  let resetComplete = $state(false);

  async function loadSecurity() {
    loading = true;
    error = '';
    try {
      security = await api.admin.getUserSecurity(detail.userID);
    } catch (cause) {
      security = null;
      error = cause instanceof Error ? cause.message : '安全摘要加载失败';
    } finally {
      loading = false;
    }
  }

  async function resetPassword(event: SubmitEvent) {
    event.preventDefault();
    resetError = '';
    resetComplete = false;
    const policyError = passwordPolicyError(password);
    if (policyError) {
      resetError = policyError;
      return;
    }
    if (password !== confirmation) {
      resetError = '两次输入的新密码不一致。';
      return;
    }
    resetting = true;
    try {
      await api.admin.resetPassword(detail.userID, password);
      password = '';
      confirmation = '';
      resetComplete = true;
      await loadSecurity();
    } catch (cause) {
      resetError = cause instanceof Error ? cause.message : '密码重置失败';
    } finally {
      resetting = false;
    }
  }

  onMount(loadSecurity);
</script>

<svelte:head><title>用户安全 - Nya</title></svelte:head>

<ResourceState {loading} {error} empty={!security} emptyTitle="暂无安全摘要" onretry={loadSecurity}>
  {#snippet children()}
    {#if security}
      <div class="grid gap-4 xl:grid-cols-2">
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><ShieldCheck size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">安全摘要</h2></div>
          <dl class="grid gap-3 sm:grid-cols-2">
            <div class="rounded-nya-sm bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">本地密码</dt><dd class="mt-2"><Badge variant={security.has_password ? 'success' : 'default'}>{security.has_password ? '已配置' : '未配置'}</Badge></dd></div>
            <div class="rounded-nya-sm bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">首次登录改密</dt><dd class="mt-2"><Badge variant={security.must_change_password ? 'warning' : 'success'}>{security.must_change_password ? '需要' : '不需要'}</Badge></dd></div>
            <div class="rounded-nya-sm bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">TOTP</dt><dd class="mt-2 text-body-medium text-nya-text-primary">{security.totp_enrolled ? `已启用 · ${security.recovery_codes_remaining} 个恢复码` : security.totp_available ? '未启用' : '系统已关闭注册'}</dd></div>
            <div class="rounded-nya-sm bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">Passkey</dt><dd class="mt-2 text-body-medium text-nya-text-primary">{security.passkeys_enrolled} 个</dd>{#if security.passkey_clone_warnings > 0}<p class="mt-1 text-small text-nya-danger">{security.passkey_clone_warnings} 个存在克隆警告</p>{/if}</div>
            <div class="rounded-nya-sm bg-nya-surface-muted p-4 sm:col-span-2"><dt class="text-small text-nya-text-tertiary">管理员 MFA 策略</dt><dd class="mt-2"><Badge variant={!security.mfa_required_for_admin || security.mfa_requirement_satisfied ? 'success' : 'danger'}>{!security.mfa_required_for_admin ? '当前不要求' : security.mfa_requirement_satisfied ? '已满足' : '未满足'}</Badge></dd></div>
          </dl>
          <p class="mt-4 text-small text-nya-text-tertiary">此页面只展示聚合状态，不返回 TOTP 密钥、恢复码、Passkey credential ID 或任何密文。</p>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><KeyRound size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">重置密码</h2></div>
          <p class="mb-4 text-body text-nya-text-secondary">设置临时密码后，该用户的旧会话和令牌会立即失效，并在下次登录时强制修改。</p>
          {#if resetError}<p class="mb-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{resetError}</p>{/if}
          {#if resetComplete}<p class="mb-3 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">密码已重置。请通过安全渠道将临时密码交给用户。</p>{/if}
          <form onsubmit={resetPassword} class="space-y-3">
            <div><Input id="admin-reset-password" label="新密码" type="password" bind:value={password} autocomplete="new-password" required /><p class="mt-1.5 text-small text-nya-text-tertiary">{PASSWORD_REQUIREMENT}</p></div>
            <Input id="admin-reset-password-confirmation" label="确认新密码" type="password" bind:value={confirmation} autocomplete="new-password" required />
            <Button type="submit" variant="secondary" requiredCapability="admin_mutations" loading={resetting}>重置密码</Button>
          </form>
        </section>
      </div>
    {/if}
  {/snippet}
</ResourceState>
