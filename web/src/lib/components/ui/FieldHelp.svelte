<script lang="ts">
  import { Tooltip } from 'bits-ui';
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

  let open = $state(false);
</script>

<Tooltip.Root bind:open delayDuration={180}>
  <Tooltip.Trigger
    type="button"
    class="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"
    aria-label={label}
    onclick={() => {
      queueMicrotask(() => { open = true; });
    }}
  >
    <CircleHelp size={15} />
  </Tooltip.Trigger>
  <Tooltip.Portal>
    <Tooltip.Content
      {id}
      role="tooltip"
      sideOffset={7}
      collisionPadding={12}
      class="z-[100] w-72 max-w-[calc(100vw-1.5rem)] rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-left text-small font-normal leading-relaxed text-nya-text-secondary shadow-nya-md"
    >
      {text}
      <Tooltip.Arrow class="fill-nya-surface stroke-nya-border" />
    </Tooltip.Content>
  </Tooltip.Portal>
</Tooltip.Root>
