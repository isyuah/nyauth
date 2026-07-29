<script lang="ts">
  import { CircleHelp } from 'lucide-svelte';

  let {
    id,
    text,
    label = '查看字段说明',
  }: {
    id: string;
    text: string;
    label?: string;
  } = $props();

  let root: HTMLSpanElement;
  let hovered = $state(false);
  let focused = $state(false);
  let pinned = $state(false);
  let dismissed = $state(false);
  let open = $derived(!dismissed && (hovered || focused || pinned));

  function toggle(event: MouseEvent) {
    if (pinned) {
      pinned = false;
      dismissed = true;
      (event.currentTarget as HTMLButtonElement).blur();
      return;
    }
    dismissed = false;
    pinned = true;
  }

  function handleKeydown(event: KeyboardEvent) {
    if (event.key !== 'Escape') return;
    event.preventDefault();
    pinned = false;
    dismissed = true;
    (event.currentTarget as HTMLButtonElement).blur();
  }

  function handleWindowClick(event: MouseEvent) {
    if (pinned && root && event.target instanceof Node && !root.contains(event.target)) {
      pinned = false;
      dismissed = true;
    }
  }
</script>

<svelte:window onclick={handleWindowClick} />

<span
  bind:this={root}
  class="relative inline-flex"
>
  <button
    type="button"
    class="inline-flex h-5 w-5 items-center justify-center rounded-full text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"
    aria-label={label}
    aria-expanded={open}
    aria-describedby={open ? id : undefined}
    onclick={toggle}
    onkeydown={handleKeydown}
    onpointerenter={() => { dismissed = false; hovered = true; }}
    onpointerleave={() => { hovered = false; dismissed = false; }}
    onfocus={() => { dismissed = false; focused = true; }}
    onblur={() => (focused = false)}
  >
    <CircleHelp size={15} />
  </button>
  {#if open}
    <span
      id={id}
      role="tooltip"
      class="absolute left-0 top-[calc(100%+0.375rem)] z-50 w-72 max-w-[calc(100vw-2rem)] rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-left text-small font-normal leading-relaxed text-nya-text-secondary shadow-nya-md"
    >
      {text}
    </span>
  {/if}
</span>
