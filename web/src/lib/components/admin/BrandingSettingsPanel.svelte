<script lang="ts">
  import { onMount } from 'svelte';
  import { api, isAPIErrorCode, isRecentAuthenticationError, type SessionInfo, type UpdateBrandingSettingsInput } from '$lib/api';
  import { brandingStore, consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { toast } from '$lib/toast';
  import { Palette } from 'lucide-svelte';

  let brandingTitle = $state('');
  let brandingLogoURL = $state('');
  let revision = $state(0);
  let loaded = $state(false);
  let saving = $state(false);
  let error = $state('');
  let conflict = $state(false);
  let reauthOpen = $state(false);
  let pendingInput = $state<UpdateBrandingSettingsInput | null>(null);
  const pendingStorageKey = 'nyauth:reauth:branding-settings';
  const returnTo = '/admin/settings/branding';

  async function loadSettings() {
    error = '';
    try {
      const current = await api.admin.getBrandingSettings();
      revision = current.revision;
      brandingTitle = current.title;
      brandingLogoURL = current.logo_url;
      conflict = false;
      loaded = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '品牌设置加载失败';
    }
  }

  async function saveBranding(event: SubmitEvent) {
    event.preventDefault();
    const input: UpdateBrandingSettingsInput = {
      expected_revision: revision,
      title: brandingTitle.trim(),
      logo_url: brandingLogoURL.trim(),
    };
    pendingInput = input;
    await executeSave(input, true);
  }

  async function executeSave(input: UpdateBrandingSettingsInput, allowReauthentication: boolean) {
    saving = true;
    error = '';
    conflict = false;
    try {
      const updated = await api.admin.updateBranding(input);
      pendingInput = null;
      brandingStore.set(updated);
      revision = updated.revision;
      brandingTitle = updated.title;
      brandingLogoURL = updated.logo_url;
      toast.success('品牌设置已保存，立即对所有实例生效。');
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

  async function retryAfterReauthentication(_session: SessionInfo) {
    if (pendingInput) await executeSave(pendingInput, false);
  }

  function persistPendingInput() {
    if (pendingInput) sessionStorage.setItem(pendingStorageKey, JSON.stringify(pendingInput));
  }

  async function restorePendingInput() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored = JSON.parse(raw) as UpdateBrandingSettingsInput;
      if (!Number.isSafeInteger(restored.expected_revision) || typeof restored.title !== 'string' || typeof restored.logo_url !== 'string') throw new TypeError('invalid stored branding settings');
      pendingInput = restored;
      revision = restored.expected_revision;
      brandingTitle = restored.title;
      brandingLogoURL = restored.logo_url;
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      await executeSave(restored, false);
    } catch {
      toast.error('无法恢复待保存的品牌设置，请重新检查表单。');
    }
  }

  onMount(async () => {
    await loadSettings();
    await restorePendingInput();
  });
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <Palette size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">品牌设置</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">修改后无需重启，立即同步到所有实例的侧栏与登录页。Logo 留空时使用内置图标。</p>
  {#if !loaded && !error}<p class="text-small text-nya-text-tertiary" role="status">正在加载品牌设置…</p>{/if}
  <form onsubmit={saveBranding} class="space-y-4">
    {#if error}<div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><span>{error}</span>{#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}>加载最新设置</Button>{/if}</div>{/if}
    <div class="grid gap-4 md:grid-cols-2">
      <Input id="branding-title" label="站点名称" bind:value={brandingTitle} required placeholder="Nya" />
      <Input id="branding-logo-url" label="Logo URL（可选）" bind:value={brandingLogoURL} placeholder="https://example.com/logo.png" />
    </div>
    <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving} disabled={!loaded}>保存品牌设置</Button>
  </form>
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改品牌设置前需要验证近期身份"
  onauthenticated={retryAfterReauthentication}
  onbeforeprovider={persistPendingInput}
/>
