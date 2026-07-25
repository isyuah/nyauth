<script lang="ts">
  import '../app.css';
  import Toast from '$lib/components/ui/Toast.svelte';
  let { children } = $props();
</script>

{@render children()}
