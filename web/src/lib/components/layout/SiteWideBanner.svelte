<script lang="ts">
  import { siteBannerStore } from '$lib/site-banner';
  import type { SiteBannerSeverity } from '$lib/api';
  import { AlertCircle, AlertTriangle, Info, X } from 'lucide-svelte';

  let siteBanner = $derived($siteBannerStore.value.site_banner);
  let visible = $derived($siteBannerStore.initialized && siteBanner !== null && !$siteBannerStore.dismissed);

  const styles: Record<SiteBannerSeverity, string> = {
    info: 'border-nya-info/25 bg-nya-info-soft text-nya-info',
    warning: 'border-nya-warning/25 bg-nya-warning-soft text-nya-warning',
    critical: 'border-nya-danger/25 bg-nya-danger-soft text-nya-danger',
  };
</script>

{#if visible && siteBanner}
  <aside data-testid="site-wide-banner" class="flex min-h-11 items-start justify-center gap-3 border-b px-4 py-2 text-small {styles[siteBanner.severity]}" role={siteBanner.severity === 'critical' ? 'alert' : 'status'} aria-live={siteBanner.severity === 'critical' ? 'assertive' : 'polite'}>
    {#if siteBanner.severity === 'critical'}<AlertCircle size={16} class="mt-0.5 shrink-0" />{:else if siteBanner.severity === 'warning'}<AlertTriangle size={16} class="mt-0.5 shrink-0" />{:else}<Info size={16} class="mt-0.5 shrink-0" />{/if}
    <div class="min-w-0 text-center sm:flex sm:items-baseline sm:gap-2 sm:text-left">
      <strong class="font-semibold">{siteBanner.title}</strong>
      <div class="site-banner-markdown ml-1 min-w-0 sm:ml-0">{@html siteBanner.message_html}</div>
    </div>
    {#if siteBanner.dismissible}
      <button type="button" onclick={() => siteBannerStore.dismiss()} class="shrink-0 rounded-nya-xs p-0.5 hover:bg-black/5" aria-label="关闭全站横幅"><X size={15} /></button>
    {/if}
</aside>
{/if}

<style>
  :global(.site-banner-markdown p) { display: inline; }
  :global(.site-banner-markdown p + p) { margin-left: 0.5rem; }
  :global(.site-banner-markdown a) { font-weight: 600; text-decoration: underline; text-underline-offset: 2px; }
  :global(.site-banner-markdown ul), :global(.site-banner-markdown ol) { display: inline-flex; flex-wrap: wrap; gap: 0.25rem 1rem; list-style-position: inside; }
  :global(.site-banner-markdown ul) { list-style-type: disc; }
  :global(.site-banner-markdown ol) { list-style-type: decimal; }
  :global(.site-banner-markdown code) { border-radius: 3px; background: rgb(0 0 0 / 0.06); padding: 0.05rem 0.25rem; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
</style>
