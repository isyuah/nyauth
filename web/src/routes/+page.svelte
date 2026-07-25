<script lang="ts">
  import { goto } from '$app/navigation';
  import { onMount } from 'svelte';
  import { sessionStore } from '$lib/stores';

  onMount(async () => {
    const session = await sessionStore.initialize();
    if (!session) return goto('/login');
    if (session.must_change_password) return goto('/change-password');
    goto(session.user.role === 'admin' ? '/admin' : '/dashboard');
  });
</script>

<div class="min-h-screen flex items-center justify-center bg-[var(--nya-bg)]">
  <div class="animate-spin rounded-full h-6 w-6 border-2 border-[var(--nya-primary)]/30 border-t-[var(--nya-primary)]"></div>
</div>
