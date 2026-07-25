<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import AppShell from '$lib/components/layout/AppShell.svelte';

  let { children } = $props();
  let authorized = $state(false);
  let loading = $state(true);

  onMount(async () => {
    const session = await sessionStore.initialize();
    if (!session) goto(`/login?return_to=${encodeURIComponent('/admin')}`);
    else if (session.must_change_password) goto('/change-password');
    else if (session.user.role !== 'admin') goto('/dashboard');
    else authorized = true;
    loading = false;
  });
</script>

{#if loading}
  <div class="min-h-screen flex items-center justify-center bg-[var(--nya-bg)]">
    <div class="animate-spin rounded-full h-6 w-6 border-2 border-[var(--nya-primary)]/30 border-t-[var(--nya-primary)]"></div>
  </div>
{:else if authorized}
  <AppShell>{@render children()}</AppShell>
{/if}
