<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import CopyButton from './CopyButton.svelte';
  import Input from './Input.svelte';

  let {
    open = $bindable(false),
    title = '确认操作',
    description,
    confirmLabel = '确认',
    confirmVariant = 'danger',
    confirmationText = '',
    error = '',
    onconfirm,
  }: {
    open?: boolean;
    title?: string;
    description: string;
    confirmLabel?: string;
    confirmVariant?: 'primary' | 'danger';
    confirmationText?: string;
    error?: string;
    onconfirm: () => void | Promise<void>;
  } = $props();

  let entered = $state('');
  let pending = $state(false);
  let allowed = $derived(!confirmationText || entered === confirmationText);
  const componentId = $props.id();
  const confirmationInputId = `${componentId}-confirmation`;

  $effect(() => {
    if (!open) entered = '';
  });

  async function confirm() {
    if (!allowed || pending) return;
    pending = true;
    try {
      await onconfirm();
      open = false;
    } catch {
      // The caller owns the error message; keep the dialog open for correction/retry.
    } finally {
      pending = false;
    }
  }
</script>

<Modal bind:open size="sm" {title} {description}>
  <div class="space-y-4">
    {#if confirmationText}
      <div class="space-y-1.5">
        <p class="text-small text-nya-text-secondary">复制并输入以下文本以确认：</p>
        <div class="flex items-center gap-2 rounded-nya-sm border border-nya-border bg-nya-surface-muted px-3 py-1.5">
          <code class="min-w-0 flex-1 break-all font-mono text-small text-nya-text-primary">{confirmationText}</code>
          <CopyButton value={confirmationText} label="复制确认文本" />
        </div>
      </div>
      <Input
        id={confirmationInputId}
        label={`输入“${confirmationText}”以确认`}
        bind:value={entered}
        autocomplete="off"
        placeholder="粘贴或输入上方文本"
      />
    {/if}
    {#if error}
      <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>
    {/if}
    <div class="flex justify-end gap-2 pt-1">
      <Button variant="secondary" onclick={() => (open = false)} disabled={pending}>取消</Button>
      <Button variant={confirmVariant} onclick={confirm} loading={pending} disabled={!allowed}>{confirmLabel}</Button>
    </div>
  </div>
</Modal>
