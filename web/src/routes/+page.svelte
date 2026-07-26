<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';

  let error = $state('');
  let loading = $state(true);

  async function routeSession() {
    loading = true;
    error = '';
    try {
      const session = await sessionStore.initialize(true);
      if (!session) await goto('/login');
      else if (session.must_change_password) await goto('/change-password');
      else await goto(session.user.role === 'admin' ? '/admin' : '/dashboard');
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '无法连接认证服务';
      loading = false;
    }
  }

  onMount(routeSession);
</script>

<div class="min-h-screen bg-nya-bg p-6">
  <div class="mx-auto max-w-xl pt-24">
    <ResourceState {loading} {error} onretry={routeSession}>{#snippet children()}{/snippet}</ResourceState>
  </div>
</div>
