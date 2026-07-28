<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { initializeBranding } from '$lib/stores';
  import { serviceStatusStore } from '$lib/service-control';
  import ServiceStatusBanner from '$lib/components/layout/ServiceStatusBanner.svelte';
  import Toast from '$lib/components/ui/Toast.svelte';
  let { children } = $props();
  onMount(() => {
    void initializeBranding();
    return serviceStatusStore.startPolling();
  });
</script>

<ServiceStatusBanner />
{@render children()}
<Toast />
