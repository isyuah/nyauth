<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { initializeBranding } from '$lib/stores';
  import { announcementStore } from '$lib/announcement';
  import { serviceStatusStore } from '$lib/service-control';
  import SiteAnnouncementBanner from '$lib/components/layout/SiteAnnouncementBanner.svelte';
  import ServiceStatusBanner from '$lib/components/layout/ServiceStatusBanner.svelte';
  import Toast from '$lib/components/ui/Toast.svelte';
  let { children } = $props();
  onMount(() => {
    void initializeBranding();
    const stopAnnouncements = announcementStore.start();
    const stopServiceStatus = serviceStatusStore.startPolling();
    return () => {
      stopAnnouncements();
      stopServiceStatus();
    };
  });
</script>

<SiteAnnouncementBanner />
<ServiceStatusBanner />
{@render children()}
<Toast />
