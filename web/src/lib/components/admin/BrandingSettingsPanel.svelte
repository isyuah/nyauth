<script lang="ts">
  import { api } from '$lib/api';
  import { brandingStore } from '$lib/stores';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { Palette } from 'lucide-svelte';

  let brandingTitle = $state('');
  let brandingLogoURL = $state('');
  let saving = $state(false);
  let error = $state('');
  let saved = $state(false);
  let synced = false;

  $effect(() => {
    const branding = $brandingStore;
    if (!synced && branding.title) {
      brandingTitle = branding.title;
      brandingLogoURL = branding.logo_url;
      synced = true;
    }
  });

  async function saveBranding(event: SubmitEvent) {
    event.preventDefault();
    saving = true;
    error = '';
    saved = false;
    try {
      const updated = await api.admin.updateBranding({
        title: brandingTitle.trim(),
        logo_url: brandingLogoURL.trim(),
      });
      brandingStore.set(updated);
      brandingTitle = updated.title;
      brandingLogoURL = updated.logo_url;
      saved = true;
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '保存失败';
    } finally {
      saving = false;
    }
  }
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <Palette size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">品牌设置</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">修改后无需重启，立即同步到所有实例的侧栏与登录页。Logo 留空时使用内置图标。</p>
  <form onsubmit={saveBranding} class="space-y-4">
    {#if error}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
    {#if saved}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">品牌设置已保存，立即对所有实例生效。</p>{/if}
    <div class="grid gap-4 md:grid-cols-2">
      <Input id="branding-title" label="站点名称" bind:value={brandingTitle} required placeholder="Nya" />
      <Input id="branding-logo-url" label="Logo URL（可选）" bind:value={brandingLogoURL} placeholder="https://example.com/logo.png" />
    </div>
    <Button type="submit" variant="primary" loading={saving}>保存品牌设置</Button>
  </form>
</section>
