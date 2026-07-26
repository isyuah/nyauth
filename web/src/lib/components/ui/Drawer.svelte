<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Dialog } from 'bits-ui';
  import { X } from 'lucide-svelte';

  let {
    open = $bindable(false),
    title = '',
    description = '',
    width = '480px',
    children,
  }: {
    open?: boolean;
    title?: string;
    description?: string;
    width?: string;
    children: Snippet;
  } = $props();
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="fixed inset-0 z-50 bg-black/30 backdrop-blur-[2px]" />
    <Dialog.Content
      class="fixed inset-y-0 right-0 z-50 h-full max-w-[92vw] overflow-y-auto bg-nya-surface outline-none"
      style="width: {width}; box-shadow: var(--nya-shadow-popup);"
    >
      <div class="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-nya-divider bg-nya-surface px-6 py-4">
        <div>
          <Dialog.Title level={2} class="text-[16px] font-semibold text-nya-text-primary">{title}</Dialog.Title>
          {#if description}
            <Dialog.Description class="mt-1 text-[13px] text-nya-text-secondary">{description}</Dialog.Description>
          {/if}
        </div>
        <Dialog.Close
          class="shrink-0 rounded-lg p-1.5 text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-text-primary"
          aria-label="关闭侧边栏"
        >
          <X size={18} />
        </Dialog.Close>
      </div>
      <div class="px-6 py-5">
        {@render children()}
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
