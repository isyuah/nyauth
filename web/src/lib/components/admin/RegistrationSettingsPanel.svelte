<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { api, isAPIErrorCode, isRecentAuthenticationError, type RegistrationMode, type RegistrationSettings, type UpdateRegistrationSettingsInput } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { toast } from '$lib/toast';
  import { UserPlus } from 'lucide-svelte';

  let { returnTo = '/admin/settings/registration' }: { returnTo?: string } = $props();

  const pendingSettingsStorageKey = 'nyauth:reauth:registration-settings';
  let mode = $state<RegistrationMode>('closed');
  let requireVerification = $state(true);
  let domains = $state('');
  let pendingTTL = $state('72h');
  let inviteTTL = $state('168h');
  let inviteMaxUses = $state('1');
  let revision = $state(0);
  let loaded = $state(false);
  let loadError = $state('');
  let saving = $state(false);
  let error = $state('');
  let inviteMaxUsesError = $state('');
  let conflict = $state(false);
  let reauthOpen = $state(false);
  let pendingSettings = $state<UpdateRegistrationSettingsInput | null>(null);

  async function loadSettings() {
    loadError = '';
    try {
      const current = await api.admin.getRegistrationSettings();
      applySettings(current);
      loaded = true;
    } catch (cause) {
      loadError = cause instanceof Error ? cause.message : '注册设置加载失败';
    }
  }

  function applySettings(settings: RegistrationSettings) {
    revision = settings.revision;
    mode = settings.mode;
    requireVerification = settings.require_email_verification;
    domains = settings.allowed_email_domains.join('\n');
    pendingTTL = settings.pending_registration_ttl;
    inviteTTL = settings.invite_default_ttl;
    inviteMaxUses = String(settings.invite_default_max_uses);
  }

  async function saveSettings(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    inviteMaxUsesError = '';
    conflict = false;
    const maxUses = Number.parseInt(inviteMaxUses.trim(), 10);
    if (!Number.isSafeInteger(maxUses) || maxUses < 1) {
      inviteMaxUsesError = '邀请默认可用次数必须是不小于 1 的整数。';
      toast.error(inviteMaxUsesError);
      await tick();
      document.getElementById('registration-invite-max-uses')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      document.getElementById('registration-invite-max-uses')?.focus({ preventScroll: true });
      return;
    }
    const payload: UpdateRegistrationSettingsInput = {
      expected_revision: revision,
      mode,
      require_email_verification: mode === 'open' ? true : requireVerification,
      allowed_email_domains: domains.split('\n').map((line) => line.trim()).filter(Boolean),
      pending_registration_ttl: pendingTTL.trim(),
      invite_default_ttl: inviteTTL.trim(),
      invite_default_max_uses: maxUses,
    };
    pendingSettings = payload;
    await executeSave(payload, true);
  }

  async function executeSave(payload: UpdateRegistrationSettingsInput, allowReauthentication: boolean) {
    saving = true;
    try {
      const updated = await api.admin.updateRegistrationSettings(payload);
      pendingSettings = null;
      applySettings(updated);
      toast.success('注册设置已保存，立即对所有实例生效。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        conflict = true;
        error = '设置已被其他管理员修改。当前表单草稿已保留，请加载最新设置后重新核对。';
      } else {
        toast.error(cause instanceof Error ? cause.message : '保存失败');
      }
    } finally {
      saving = false;
    }
  }

  async function retrySave() {
    if (pendingSettings) await executeSave(pendingSettings, false);
  }

  function persistPendingSettings() {
    if (pendingSettings) sessionStorage.setItem(pendingSettingsStorageKey, JSON.stringify(pendingSettings));
  }

  async function restorePendingSettings() {
    const raw = sessionStorage.getItem(pendingSettingsStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingSettingsStorageKey);
    try {
      const restored = JSON.parse(raw) as UpdateRegistrationSettingsInput;
      pendingSettings = restored;
      revision = restored.expected_revision;
      mode = restored.mode;
      requireVerification = restored.require_email_verification;
      domains = restored.allowed_email_domains.join('\n');
      pendingTTL = restored.pending_registration_ttl;
      inviteTTL = restored.invite_default_ttl;
      inviteMaxUses = String(restored.invite_default_max_uses);
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      await executeSave(restored, false);
    } catch {
      toast.error('无法恢复待保存的注册设置，请重新检查表单。');
    }
  }

  onMount(async () => {
    await loadSettings();
    await restorePendingSettings();
  });
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <UserPlus size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">注册设置</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">控制自助注册的开关与邀请默认值，保存后免重启即时生效。开启注册要求 SMTP 子系统已配置。</p>
  {#if loadError}
    <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{loadError}</p>
  {:else if !loaded}
    <p class="text-small text-nya-text-tertiary">加载中…</p>
  {:else}
    <form onsubmit={saveSettings} class="space-y-4">
      {#if error}<div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><span>{error}</span>{#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}>加载最新设置</Button>{/if}</div>{/if}
      <fieldset>
        <legend class="mb-2 text-body-medium text-nya-text-primary">注册模式</legend>
        <div class="grid gap-2 sm:grid-cols-3">
          {#each [
            { value: 'closed', label: '关闭', description: '仅管理员可创建账号（默认）' },
            { value: 'invite_only', label: '邀请制', description: '需要有效邀请码才能注册' },
            { value: 'open', label: '开放', description: '任何人都可注册，强制邮箱验证' },
          ] as option}
            <label class="flex cursor-pointer items-start gap-2 rounded-nya-sm border border-nya-border px-3 py-2 {mode === option.value ? 'border-nya-primary bg-nya-primary-soft' : ''}">
              <input type="radio" name="registration-mode" value={option.value} bind:group={mode} class="mt-0.5" />
              <span><span class="block text-small font-semibold text-nya-text-primary">{option.label}</span><span class="block text-micro text-nya-text-tertiary">{option.description}</span></span>
            </label>
          {/each}
        </div>
      </fieldset>
      <label class="flex cursor-pointer items-start gap-2">
        <input type="checkbox" checked={mode === 'open' ? true : requireVerification} disabled={mode === 'open'} onchange={(event) => (requireVerification = event.currentTarget.checked)} class="mt-0.5 rounded" />
        <span><span class="block text-body text-nya-text-primary">要求邮箱验证</span><span class="block text-small text-nya-text-tertiary">注册后必须完成验证邮件确认才能登录；开放模式下强制开启。</span></span>
      </label>
      <div>
        <label for="registration-domains" class="mb-1.5 block text-body-medium text-nya-text-primary">允许的邮箱域名（每行一个，留空不限制）</label>
        <textarea id="registration-domains" bind:value={domains} rows="3" placeholder="corp.example.com" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea>
      </div>
      <div class="grid gap-4 sm:grid-cols-3">
        <Input id="registration-pending-ttl" label="待验证注册有效期" bind:value={pendingTTL} placeholder="72h" />
        <Input id="registration-invite-ttl" label="邀请默认有效期" bind:value={inviteTTL} placeholder="168h" />
        <Input id="registration-invite-max-uses" label="邀请默认可用次数" bind:value={inviteMaxUses} placeholder="1" inputmode="numeric" error={inviteMaxUsesError} oninput={() => (inviteMaxUsesError = '')} />
      </div>
      <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存注册设置</Button>
    </form>
  {/if}
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改注册策略前需要验证近期身份"
  onauthenticated={retrySave}
  onbeforeprovider={persistPendingSettings}
/>
