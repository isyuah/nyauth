<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { authStore } from '$lib/stores';
  import { api } from '$lib/api';
  import AppShell from '$lib/components/layout/AppShell.svelte';

  let { children } = $props();
  let authorized = $state(false);
  let loading = $state(true);

  onMount(async () => {
    if (!$authStore.token) {
      goto('/login');
      return;
    }
    try {
      const me = await api.getMe();
      if (me.role !== 'admin') {
        goto('/profile');
        return;
      }
      authorized = true;
    } catch {
      goto('/login');
    } finally {
      loading = false;
    }
  });
</script>

{#if loading}
  <div class="min-h-screen flex items-center justify-center bg-[var(--nya-bg)]">
    <div class="animate-spin rounded-full h-6 w-6 border-2 border-[var(--nya-primary)]/30 border-t-[var(--nya-primary)]"></div>
  </div>
{:else if authorized}
  <AppShell>{@render children()}</AppShell>
{/if}
