<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isRecentAuthenticationError,
    missingAdminsFromError,
    type SecuritySettings,
  } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { ShieldCheck } from 'lucide-svelte';

  let { returnTo = '/admin/settings/security' }: { returnTo?: string } = $props();

  const pendingSettingsStorageKey = 'nyauth:reauth:security-settings';

  let totpEnabled = $state(true);
  let passkeysEnabled = $state(true);
  let requireMFAForAdmins = $state(false);
  let loaded = $state(false);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let saved = $state(false);
  let missingAdmins = $state<string[]>([]);
  let reauthOpen = $state(false);
  let pendingSettings = $state<SecuritySettings | null>(null);

  onMount(async () => {
    await loadSettings();
    await restorePendingSettings();
  });

  async function loadSettings() {
    loading = true;
    error = '';
    try {
      const current = await api.admin.getSecuritySettings();
      totpEnabled = current.totp_enabled;
      passkeysEnabled = current.passkeys_enabled;
      requireMFAForAdmins = current.require_mfa_for_admins;
      loaded = true;
    } catch (cause) {
      loaded = false;
      error = cause instanceof Error ? cause.message : '登录安全策略加载失败';
    } finally {
      loading = false;
    }
  }

  async function saveSettings(event: SubmitEvent) {
    event.preventDefault();
    const payload: SecuritySettings = {
      totp_enabled: totpEnabled,
      passkeys_enabled: passkeysEnabled,
      require_mfa_for_admins: requireMFAForAdmins,
    };
    pendingSettings = payload;
    await executeSave(payload, true);
  }

  async function executeSave(payload: SecuritySettings, allowReauthentication: boolean) {
    saving = true;
    error = '';
    saved = false;
    missingAdmins = [];
    try {
      const updated = await api.admin.updateSecuritySettings(payload);
      pendingSettings = null;
      totpEnabled = updated.totp_enabled;
      passkeysEnabled = updated.passkeys_enabled;
      requireMFAForAdmins = updated.require_mfa_for_admins;
      saved = true;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
        return;
      }
      missingAdmins = missingAdminsFromError(cause);
      error = cause instanceof Error ? cause.message : '登录安全策略保存失败';
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
      const restored = JSON.parse(raw) as Partial<SecuritySettings>;
      if (typeof restored.totp_enabled !== 'boolean'
        || typeof restored.passkeys_enabled !== 'boolean'
        || typeof restored.require_mfa_for_admins !== 'boolean') {
        throw new TypeError('invalid stored security settings');
      }
      const validated: SecuritySettings = {
        totp_enabled: restored.totp_enabled,
        passkeys_enabled: restored.passkeys_enabled,
        require_mfa_for_admins: restored.require_mfa_for_admins,
      };
      pendingSettings = validated;
      totpEnabled = validated.totp_enabled;
      passkeysEnabled = validated.passkeys_enabled;
      requireMFAForAdmins = validated.require_mfa_for_admins;
      const providerError = consumeProviderAuthError();
      if (providerError) {
        error = providerError.message;
        return;
      }
      await executeSave(validated, false);
    } catch {
      error = '无法恢复待保存的登录安全策略，请重新检查设置。';
    }
  }
</script>

<section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <ShieldCheck size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">登录安全策略</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">控制动态验证码、Passkey 注册和管理员强制 MFA，保存后无需重启即可同步到所有实例。</p>

  {#if loading}
    <p class="text-small text-nya-text-tertiary" role="status">正在加载登录安全策略…</p>
  {:else if !loaded}
    <div class="flex items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2">
      <p class="text-small text-nya-danger" role="alert">{error}</p>
      <Button variant="ghost" size="sm" onclick={loadSettings}>重试</Button>
    </div>
  {:else}
    <form onsubmit={saveSettings} class="space-y-4">
      {#if error}
        <div class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">
          <p>{error}</p>
          {#if missingAdmins.length > 0}
            <p class="mt-2 font-semibold">以下活动管理员尚未启用 MFA：</p>
            <ul class="mt-1 list-inside list-disc font-mono">
              {#each missingAdmins as username}<li>{username}</li>{/each}
            </ul>
          {/if}
        </div>
      {/if}
      {#if saved}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">登录安全策略已保存，立即对所有实例生效。</p>{/if}

      <div class="space-y-4 rounded-nya-sm bg-nya-surface-muted p-4">
        <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
          <div class="max-w-2xl">
            <p class="text-body-medium font-semibold text-nya-text-primary">允许注册动态验证码</p>
            <p class="mt-1 text-small text-nya-text-secondary">关闭后只阻止新的 TOTP 注册，已经启用的动态验证码仍可继续登录和管理。</p>
          </div>
          <Switch bind:checked={totpEnabled} label="允许 TOTP 注册" />
        </div>

        <div class="border-t border-nya-divider pt-4">
          <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
            <div class="max-w-2xl">
              <p class="text-body-medium font-semibold text-nya-text-primary">允许注册 Passkey</p>
              <p class="mt-1 text-small text-nya-text-secondary">关闭后只阻止新的 Passkey 注册；已经注册的 Passkey 仍可用于登录、MFA 和重新认证。</p>
            </div>
            <Switch bind:checked={passkeysEnabled} label="允许 Passkey 注册" />
          </div>
        </div>

        <div class="border-t border-nya-divider pt-4">
          <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
            <div class="max-w-2xl">
              <p class="text-body-medium font-semibold text-nya-text-primary">要求所有活动管理员启用 MFA</p>
              <p class="mt-1 text-small text-nya-text-secondary">开启前，后端会核对每位活动管理员；未完成配置的账号会在下方明确列出。</p>
            </div>
            <Switch bind:checked={requireMFAForAdmins} label="管理员强制 MFA" />
          </div>
          <p class="mt-2 text-small text-nya-text-tertiary">该策略接受已注册的动态验证码或 Passkey；保存时后端会验证所有活动管理员是否至少拥有一种因素。</p>
        </div>
      </div>

      <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存登录安全策略</Button>
    </form>
  {/if}
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改登录安全策略前需要验证最近 10 分钟内的身份"
  onauthenticated={retrySave}
  onbeforeprovider={persistPendingSettings}
/>
