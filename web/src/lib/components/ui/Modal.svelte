<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Dialog } from 'bits-ui';
  import { X } from 'lucide-svelte';

  let {
    open = $bindable(false),
    size = 'md',
    title = '',
    description = '',
    dismissible = true,
    children,
  }: {
    open?: boolean;
    size?: 'sm' | 'md' | 'lg';
    title?: string;
    description?: string;
    dismissible?: boolean;
    children: Snippet;
  } = $props();

  const widths = { sm: '420px', md: '560px', lg: '720px' };
</script>

<Dialog.Root bind:open>
  <Dialog.Portal>
    <Dialog.Overlay class="fixed inset-0 z-50 bg-black/30 backdrop-blur-[2px]" />
    <Dialog.Content
      class="fixed left-1/2 top-1/2 z-50 max-h-[calc(100vh-2rem)] w-[calc(100%-2rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto bg-nya-surface outline-none"
      style="max-width: {widths[size]}; border-radius: var(--nya-radius-lg); box-shadow: var(--nya-shadow-popup);"
      onEscapeKeydown={(event) => { if (!dismissible) event.preventDefault(); }}
      onInteractOutside={(event) => { if (!dismissible) event.preventDefault(); }}
    >
      {#if title}
        <div class="flex items-start justify-between gap-4 border-b border-nya-divider px-6 py-4">
          <div>
            <Dialog.Title level={2} class="text-[16px] font-semibold text-nya-text-primary">{title}</Dialog.Title>
            {#if description}
              <Dialog.Description class="mt-1 text-[13px] text-nya-text-secondary">{description}</Dialog.Description>
            {/if}
          </div>
          {#if dismissible}
            <Dialog.Close
              class="shrink-0 rounded-lg p-1.5 text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-text-primary"
              aria-label="关闭对话框"
            >
              <X size={18} />
            </Dialog.Close>
          {/if}
        </div>
      {/if}
      <div class="px-6 py-5">
        {@render children()}
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
