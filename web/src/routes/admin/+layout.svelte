<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import AppShell from '$lib/components/layout/AppShell.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';

  let { children } = $props();
  let authorized = $state(false);
  let loading = $state(true);
  let error = $state('');

  function returnPath(): string {
    return `${$page.url.pathname}${$page.url.search}${$page.url.hash}`;
  }

  async function authorize() {
    loading = true;
    error = '';
    try {
      const session = await sessionStore.initialize(true);
      if (!session) {
        await goto(`/login?return_to=${encodeURIComponent(returnPath())}`);
      } else if (session.must_change_password) {
        await goto(`/change-password?return_to=${encodeURIComponent(returnPath())}`);
      } else if (session.user.role !== 'admin') {
        await goto('/dashboard');
      } else {
        authorized = true;
      }
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法验证当前会话';
    } finally {
      loading = false;
    }
  }

  onMount(authorize);
</script>

{#if loading || error}
  <div class="min-h-screen bg-nya-bg p-6">
    <div class="mx-auto max-w-2xl pt-24">
      <ResourceState {loading} {error} onretry={authorize}>{#snippet children()}{/snippet}</ResourceState>
    </div>
  </div>
{:else if authorized}
  <AppShell section="admin">{@render children()}</AppShell>
{/if}
