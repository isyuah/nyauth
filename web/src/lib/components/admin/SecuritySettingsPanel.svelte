<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    missingAdminsFromError,
    type SecuritySettings,
    type UpdateSecuritySettingsInput,
  } from '$lib/api';
  import { consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { toast } from '$lib/toast';
  import { ShieldCheck } from 'lucide-svelte';

  let { returnTo = '/admin/settings/security' }: { returnTo?: string } = $props();

  const pendingSettingsStorageKey = 'nyauth:reauth:security-settings';

  let totpEnabled = $state(true);
  let passkeysEnabled = $state(true);
  let requireMFAForAdmins = $state(false);
  let trustedDevicesEnabled = $state(true);
  let trustedDeviceTTLDays = $state('30');
  let revision = $state(0);
  let loaded = $state(false);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  let conflict = $state(false);
  let missingAdmins = $state<string[]>([]);
  let reauthOpen = $state(false);
  let pendingSettings = $state<UpdateSecuritySettingsInput | null>(null);

  onMount(async () => {
    await loadSettings();
    await restorePendingSettings();
  });

  async function loadSettings() {
    loading = true;
    error = '';
    try {
      const current = await api.admin.getSecuritySettings();
      revision = current.revision;
      totpEnabled = current.totp_enabled;
      passkeysEnabled = current.passkeys_enabled;
      requireMFAForAdmins = current.require_mfa_for_admins;
      trustedDevicesEnabled = current.trusted_devices_enabled;
      trustedDeviceTTLDays = trustedDeviceDays(current.trusted_device_ttl);
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
    const trustedDays = Number(trustedDeviceTTLDays);
    if (!Number.isInteger(trustedDays) || trustedDays < 1 || trustedDays > 90) {
      toast.error('可信浏览器有效期须为 1 至 90 天的整数。');
      return;
    }
    const payload: UpdateSecuritySettingsInput = {
      expected_revision: revision,
      totp_enabled: totpEnabled,
      passkeys_enabled: passkeysEnabled,
      require_mfa_for_admins: requireMFAForAdmins,
      trusted_devices_enabled: trustedDevicesEnabled,
      trusted_device_ttl: `${trustedDays * 24}h`,
    };
    pendingSettings = payload;
    await executeSave(payload, true);
  }

  async function executeSave(payload: UpdateSecuritySettingsInput, allowReauthentication: boolean) {
    saving = true;
    error = '';
    conflict = false;
    missingAdmins = [];
    try {
      const updated = await api.admin.updateSecuritySettings(payload);
      pendingSettings = null;
      revision = updated.revision;
      totpEnabled = updated.totp_enabled;
      passkeysEnabled = updated.passkeys_enabled;
      requireMFAForAdmins = updated.require_mfa_for_admins;
      trustedDevicesEnabled = updated.trusted_devices_enabled;
      trustedDeviceTTLDays = trustedDeviceDays(updated.trusted_device_ttl);
      toast.success('登录安全策略已保存，立即对所有实例生效。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
        return;
      }
      if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        conflict = true;
        error = '设置已被其他管理员修改。当前表单草稿已保留，请加载最新设置后重新核对。';
        return;
      }
      missingAdmins = missingAdminsFromError(cause);
      const message = cause instanceof Error ? cause.message : '登录安全策略保存失败';
      if (missingAdmins.length > 0) error = message;
      else toast.error(message);
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
      const restored = JSON.parse(raw) as Partial<UpdateSecuritySettingsInput>;
      if (typeof restored.totp_enabled !== 'boolean'
        || typeof restored.passkeys_enabled !== 'boolean'
        || typeof restored.require_mfa_for_admins !== 'boolean'
        || !Number.isSafeInteger(restored.expected_revision)) {
        throw new TypeError('invalid stored security settings');
      }
      const validated: UpdateSecuritySettingsInput = {
        expected_revision: restored.expected_revision as number,
        totp_enabled: restored.totp_enabled,
        passkeys_enabled: restored.passkeys_enabled,
        require_mfa_for_admins: restored.require_mfa_for_admins,
        trusted_devices_enabled: restored.trusted_devices_enabled !== false,
        trusted_device_ttl: typeof restored.trusted_device_ttl === 'string' && restored.trusted_device_ttl ? restored.trusted_device_ttl : '720h',
      };
      pendingSettings = validated;
      revision = validated.expected_revision;
      totpEnabled = validated.totp_enabled;
      passkeysEnabled = validated.passkeys_enabled;
      requireMFAForAdmins = validated.require_mfa_for_admins;
      trustedDevicesEnabled = validated.trusted_devices_enabled !== false;
      trustedDeviceTTLDays = trustedDeviceDays(validated.trusted_device_ttl || '720h');
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      await executeSave(validated, false);
    } catch {
      toast.error('无法恢复待保存的登录安全策略，请重新检查设置。');
    }
  }

  function trustedDeviceDays(duration: string): string {
    const hours = Number.parseFloat(duration.replace(/h.*$/, ''));
    if (!Number.isFinite(hours)) return '30';
    return String(Math.min(90, Math.max(1, Math.round(hours / 24))));
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
          {#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}>加载最新设置</Button>{/if}
          {#if missingAdmins.length > 0}
            <p class="mt-2 font-semibold">以下活动管理员尚未启用 MFA：</p>
            <ul class="mt-1 list-inside list-disc font-mono">
              {#each missingAdmins as username}<li>{username}</li>{/each}
            </ul>
          {/if}
        </div>
      {/if}

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

        <div class="border-t border-nya-divider pt-4">
          <div class="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
            <div class="max-w-2xl">
              <p class="text-body-medium font-semibold text-nya-text-primary">允许信任浏览器</p>
              <p class="mt-1 text-small text-nya-text-secondary">用户完成 MFA 后可信任当前浏览器。信任只跳过后续登录的第二项验证，不会跳过密码、Provider、Passkey 主验证或近期重新认证。</p>
            </div>
            <Switch bind:checked={trustedDevicesEnabled} label="允许信任浏览器" />
          </div>
          <div class="mt-4 max-w-xs">
            <Input
              id="trusted-device-ttl-days"
              label="信任有效期（天）"
              bind:value={trustedDeviceTTLDays}
              type="number"
              inputmode="numeric"
              min={1}
              max={90}
              step={1}
              disabled={!trustedDevicesEnabled}
              help="范围 1 至 90 天。缩短后会立即按设备最初创建时间重新计算截止日期，延长不会续期已有设备。"
              required
            />
          </div>
          {#if !trustedDevicesEnabled}
            <p class="mt-3 rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning">保存为关闭状态会立即撤销全部用户的可信浏览器记录；之后重新开启不会恢复。</p>
          {/if}
        </div>
      </div>

      <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存登录安全策略</Button>
    </form>
  {/if}
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改登录安全策略前需要验证近期身份"
  onauthenticated={retrySave}
  onbeforeprovider={persistPendingSettings}
/>
