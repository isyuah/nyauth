<script lang="ts">
  import { onMount } from 'svelte';
  import { api, isAPIErrorCode, isRecentAuthenticationError, type PrimaryTextColor, type SessionInfo, type UpdateBrandingSettingsInput } from '$lib/api';
  import { brandingStore, consumeProviderAuthError } from '$lib/stores';
  import { contrastRatio, normalizeHexColor, primaryPalette, selectedTextColor } from '$lib/theme';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import { toast } from '$lib/toast';
  import { CheckCircle2, Contrast, Moon, Palette, Sun } from 'lucide-svelte';

  let brandingTitle = $state('');
  let primaryColor = $state('#704DE8');
  let primaryTextPreference = $state<PrimaryTextColor>('auto');
  let lightLogoURL = $state('');
  let darkLogoURL = $state('');
  let faviconURL = $state('');
  let revision = $state(0);
  let loaded = $state(false);
  let saving = $state(false);
  let error = $state('');
  let conflict = $state(false);
  let reauthOpen = $state(false);
  let pendingInput = $state<UpdateBrandingSettingsInput | null>(null);
  const pendingStorageKey = 'nyauth:reauth:branding-settings';
  const returnTo = '/admin/settings/branding';
  const primaryTextOptions = [
    { value: 'auto', label: '自动选择高对比度文字' },
    { value: 'white', label: '始终使用白色文字' },
    { value: 'black', label: '始终使用黑色文字' },
  ];

  let validPrimaryColor = $derived(normalizeHexColor(primaryColor));
  let previewPrimary = $derived(validPrimaryColor || '#704DE8');
  let primaryText = $derived(selectedTextColor(previewPrimary, primaryTextPreference));
  let primaryContrast = $derived(contrastRatio(previewPrimary, primaryText));

  function applySettings(current: Awaited<ReturnType<typeof api.admin.getBrandingSettings>>) {
    revision = current.revision;
    brandingTitle = current.title;
    primaryColor = current.primary_color;
    primaryTextPreference = current.primary_text_color;
    lightLogoURL = current.light_logo_url;
    darkLogoURL = current.dark_logo_url;
    faviconURL = current.favicon_url;
  }

  async function loadSettings() {
    error = '';
    try {
      const current = await api.admin.getBrandingSettings();
      applySettings(current);
      conflict = false;
      loaded = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '品牌设置加载失败';
    }
  }

  function currentInput(): UpdateBrandingSettingsInput {
    return {
      expected_revision: revision,
      title: brandingTitle.trim(),
      primary_color: primaryColor.trim(),
      primary_text_color: primaryTextPreference,
      light_logo_url: lightLogoURL.trim(),
      dark_logo_url: darkLogoURL.trim(),
      favicon_url: faviconURL.trim(),
    };
  }

  async function saveBranding(event: SubmitEvent) {
    event.preventDefault();
    const input = currentInput();
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
      applySettings(updated);
      toast.success('品牌与主题设置已保存，立即对所有实例生效。');
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

  function isStoredInput(value: unknown): value is UpdateBrandingSettingsInput {
    if (!value || typeof value !== 'object') return false;
    const input = value as Record<string, unknown>;
    return Number.isSafeInteger(input.expected_revision)
      && typeof input.title === 'string'
      && typeof input.primary_color === 'string'
      && ['auto', 'white', 'black'].includes(String(input.primary_text_color))
      && typeof input.light_logo_url === 'string'
      && typeof input.dark_logo_url === 'string'
      && typeof input.favicon_url === 'string';
  }

  async function restorePendingInput() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored: unknown = JSON.parse(raw);
      if (!isStoredInput(restored)) throw new TypeError('invalid stored branding settings');
      pendingInput = restored;
      revision = restored.expected_revision;
      brandingTitle = restored.title;
      primaryColor = restored.primary_color;
      primaryTextPreference = restored.primary_text_color;
      lightLogoURL = restored.light_logo_url;
      darkLogoURL = restored.dark_logo_url;
      faviconURL = restored.favicon_url;
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
    <h2 class="text-card-title text-nya-text-primary">品牌与主题</h2>
  </div>
  <p class="mb-5 text-body text-nya-text-secondary">配置会实时同步到所有实例。系统只接受结构化颜色和安全图片地址，不支持注入 CSS、字体或脚本。</p>
  {#if !loaded && !error}<p class="text-small text-nya-text-tertiary" role="status">正在加载品牌设置…</p>{/if}
  <form onsubmit={saveBranding} class="space-y-6">
    {#if error}<div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><span>{error}</span>{#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}>加载最新设置</Button>{/if}</div>{/if}

    <Input id="branding-title" label="站点名称" bind:value={brandingTitle} required maxlength={64} placeholder="Nya" help="用于页面标题、认证流程和事务邮件。" />

    <div class="grid gap-4 md:grid-cols-2">
      <div>
        <label for="branding-primary-color" class="mb-1.5 block text-body-medium text-nya-text-primary">主色</label>
        <div class="flex items-center gap-3">
          <input id="branding-primary-color-picker" aria-label="选择主色" type="color" bind:value={primaryColor} class="h-[38px] w-12 cursor-pointer rounded-nya-sm border border-nya-border bg-nya-surface p-1" />
          <input id="branding-primary-color" bind:value={primaryColor} maxlength={7} spellcheck="false" class="h-[38px] min-w-0 flex-1 rounded-nya-sm border bg-nya-surface px-3 font-mono text-body text-nya-text-primary outline-none transition focus:ring-2 {validPrimaryColor ? 'border-nya-border focus:border-nya-primary focus:ring-nya-primary/24' : 'border-nya-danger focus:ring-nya-danger/24'}" />
        </div>
        <p class="mt-1.5 text-small {validPrimaryColor ? 'text-nya-text-tertiary' : 'text-nya-danger'}">{validPrimaryColor ? '系统会自动生成悬停、按下、柔和背景和边框色阶。' : '请输入 #RRGGBB 格式的颜色。'}</p>
      </div>
      <div>
        <Select id="branding-primary-text" label="主色文字" bind:value={primaryTextPreference} options={primaryTextOptions} />
        <p class="mt-1.5 text-small text-nya-text-tertiary">自动模式优先选择对比度更高的黑色或白色；手动模式允许按品牌视觉覆盖。</p>
      </div>
    </div>

    <div class="grid gap-4 md:grid-cols-2">
      <Input id="branding-light-logo-url" label="浅色主题 Logo" bind:value={lightLogoURL} placeholder="/media/branding/logo-light.webp" help="留空时使用深色 Logo，再回退到内置 Logo。" />
      <Input id="branding-dark-logo-url" label="深色主题 Logo" bind:value={darkLogoURL} placeholder="/media/branding/logo-dark.webp" help="留空时使用浅色 Logo，再回退到内置 Logo。" />
      <Input id="branding-favicon-url" label="Favicon" bind:value={faviconURL} placeholder="/media/branding/favicon.ico" help="留空时使用内置 favicon。" />
    </div>

    <div>
      <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 class="text-body-medium font-semibold text-nya-text-primary">实时预览</h3>
        <span class="inline-flex items-center gap-1.5 text-small {primaryContrast >= 4.5 ? 'text-nya-success' : 'text-nya-danger'}"><Contrast size={14} /> 主按钮对比度 {primaryContrast.toFixed(2)}:1 {primaryContrast >= 4.5 ? '通过 AA' : '未通过 AA'}</span>
      </div>
      <div class="grid overflow-hidden rounded-nya-md border border-nya-border lg:grid-cols-2">
        {#each ['light', 'dark'] as previewTheme}
          {@const palette = primaryPalette(previewPrimary, previewTheme as 'light' | 'dark', primaryTextPreference)}
          {@const dark = previewTheme === 'dark'}
          {@const logo = (dark ? darkLogoURL : lightLogoURL) || (dark ? lightLogoURL : darkLogoURL) || '/logo.png'}
          <div class="min-h-44 p-5 {dark ? 'bg-[#111218] text-[#F2F1F7]' : 'bg-[#FAF9FF] text-[#202235]'}" style={`--preview-primary:${palette['--nya-primary']};--preview-soft:${palette['--nya-primary-soft']};--preview-contrast:${palette['--nya-primary-contrast']}`}>
            <div class="mb-6 flex items-center justify-between gap-3"><span class="flex min-w-0 items-center gap-2.5"><img src={logo} alt="" class="h-9 w-9 object-contain" /><strong class="truncate">{brandingTitle || 'Nya'}</strong></span>{#if dark}<Moon size={16} />{:else}<Sun size={16} />{/if}</div>
            <p class="mb-3 text-sm opacity-70">使用品牌色生成的认证操作预览</p>
            <div class="flex items-center gap-2"><span class="inline-flex h-9 items-center rounded-lg px-4 text-sm font-semibold" style="background:var(--preview-primary);color:var(--preview-contrast)">继续</span><span class="inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs" style="background:var(--preview-soft);color:var(--preview-primary)"><CheckCircle2 size={13} /> 已验证</span></div>
          </div>
        {/each}
      </div>
    </div>

    <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving} disabled={!loaded || !validPrimaryColor}>保存品牌设置</Button>
  </form>
</section>

<ReauthenticationDialog
  bind:open={reauthOpen}
  {returnTo}
  description="修改品牌与主题设置前需要验证近期身份"
  onauthenticated={retryAfterReauthentication}
  onbeforeprovider={persistPendingInput}
/>
