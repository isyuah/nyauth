<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { authStore } from '$lib/stores';

  onMount(() => {
    goto($authStore.token ? '/admin' : '/login');
  });
</script>

<div class="min-h-screen flex items-center justify-center bg-nya-page">
  <div class="w-8 h-8 border-3 border-nya-primary/30 border-t-nya-primary rounded-full animate-spin"></div>
</div>
