<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Tooltip } from 'bits-ui';

  let {
    content,
    children,
    delay = 400,
  }: {
    content: string;
    children: Snippet;
    delay?: number;
  } = $props();
</script>

<Tooltip.Root delayDuration={delay}>
  <Tooltip.Trigger class="inline-flex">{@render children()}</Tooltip.Trigger>
  <Tooltip.Portal>
    <Tooltip.Content
      sideOffset={6}
      class="z-[100] max-w-64 rounded-nya-sm bg-nya-text-primary px-2.5 py-1.5 text-small text-white shadow-nya-popup"
    >
      {content}
      <Tooltip.Arrow class="fill-nya-text-primary" />
    </Tooltip.Content>
  </Tooltip.Portal>
</Tooltip.Root>
