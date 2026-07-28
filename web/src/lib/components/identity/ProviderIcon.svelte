<script lang="ts">
  import { SiGithub, SiGoogle } from '@icons-pack/svelte-simple-icons';
  import { Globe2, KeyRound, Link2 } from 'lucide-svelte';

  let {
    type = 'generic',
    iconKey = 'auto',
    size = 20,
    label = '',
  }: {
    type?: string | null;
    iconKey?: string | null;
    size?: number;
    label?: string;
  } = $props();

  let resolved = $derived(iconKey && iconKey !== 'auto' ? iconKey : type);
</script>

<span class="inline-flex shrink-0 items-center justify-center" aria-hidden={label ? undefined : 'true'} title={label || undefined}>
  {#if resolved === 'github'}
    <SiGithub {size} color="currentColor" />
  {:else if resolved === 'google'}
    <SiGoogle {size} color="#4285F4" />
  {:else if resolved === 'link'}
    <Link2 {size} />
  {:else if resolved === 'globe'}
    <Globe2 {size} />
  {:else}
    <KeyRound {size} />
  {/if}
</span>
