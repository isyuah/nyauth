<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { initializeBranding } from '$lib/stores';
  import Toast from '$lib/components/ui/Toast.svelte';
  let { children } = $props();
  onMount(() => { void initializeBranding(); });
</script>

{@render children()}
<Toast />
