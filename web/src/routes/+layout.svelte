<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { initializeBranding } from '$lib/stores';
  import { siteBannerStore } from '$lib/site-banner';
  import { serviceStatusStore } from '$lib/service-control';
  import SiteWideBanner from '$lib/components/layout/SiteWideBanner.svelte';
  import ServiceStatusBanner from '$lib/components/layout/ServiceStatusBanner.svelte';
  import Toast from '$lib/components/ui/Toast.svelte';
  let { children } = $props();
  let globalBannerStack: HTMLDivElement | null = null;
  onMount(() => {
    void initializeBranding();
    const stopSiteBanner = siteBannerStore.start();
    const stopServiceStatus = serviceStatusStore.startPolling();
    const root = document.documentElement;
    const updateBannerHeight = () => {
      const height = globalBannerStack?.getBoundingClientRect().height ?? 0;
      root.style.setProperty('--nya-global-banner-height', `${height}px`);
    };
    const resizeObserver = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(updateBannerHeight);
    if (globalBannerStack && resizeObserver) resizeObserver.observe(globalBannerStack);
    updateBannerHeight();
    return () => {
      stopSiteBanner();
      stopServiceStatus();
      resizeObserver?.disconnect();
      root.style.removeProperty('--nya-global-banner-height');
    };
  });
</script>

<div bind:this={globalBannerStack} data-testid="global-banner-stack" class="fixed inset-x-0 top-0 z-30">
  <SiteWideBanner />
  <ServiceStatusBanner />
</div>
<div aria-hidden="true" style="height: var(--nya-global-banner-height, 0px);"></div>
{@render children()}
<Toast />
