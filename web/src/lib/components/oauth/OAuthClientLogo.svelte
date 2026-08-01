<script lang="ts">
  import { AppWindow } from 'lucide-svelte';

  let {
    name,
    url = null,
    size = 'md',
  }: {
    name: string;
    url?: string | null;
    size?: 'sm' | 'md' | 'lg';
  } = $props();

  const dimensions = {
    sm: 'h-10 w-10 rounded-nya-sm',
    md: 'h-12 w-12 rounded-nya-md',
    lg: 'h-16 w-16 rounded-nya-md',
  } as const;

  let initial = $derived(name.trim().charAt(0).toLocaleUpperCase() || '应');
</script>

<span class="flex shrink-0 items-center justify-center overflow-hidden border border-nya-border bg-nya-blue-soft font-semibold text-nya-blue {dimensions[size]}">
  {#if url}
    <img src={url} alt={`${name || '应用'} Logo`} class="h-full w-full object-cover" />
  {:else if initial}
    <span aria-hidden="true">{initial}</span>
    <span class="sr-only">{name || '应用'}未设置 Logo</span>
  {:else}
    <AppWindow size={20} aria-hidden="true" />
  {/if}
</span>
