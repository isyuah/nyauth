<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { authStore } from '$lib/stores';
  import { api } from '$lib/api';

  onMount(async () => {
    if (!$authStore.token) {
      goto('/login');
      return;
    }
    try {
      const me = await api.getMe();
      goto(me.role === 'admin' ? '/admin' : '/dashboard');
    } catch {
      goto('/login');
    }
  });
</script>

<div class="min-h-screen flex items-center justify-center bg-[var(--nya-bg)]">
  <div class="animate-spin rounded-full h-6 w-6 border-2 border-[var(--nya-primary)]/30 border-t-[var(--nya-primary)]"></div>
</div>
