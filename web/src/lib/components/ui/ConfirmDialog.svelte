<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';

  let {
    open = $bindable(false),
    title = '确认操作',
    description,
    confirmLabel = '确认',
    confirmationText = '',
    error = '',
    onconfirm,
  }: {
    open?: boolean;
    title?: string;
    description: string;
    confirmLabel?: string;
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
      <Input
        id={confirmationInputId}
        label={`输入“${confirmationText}”以确认`}
        bind:value={entered}
        autocomplete="off"
        placeholder={confirmationText}
      />
    {/if}
    {#if error}
      <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>
    {/if}
    <div class="flex justify-end gap-2 pt-1">
      <Button variant="secondary" onclick={() => (open = false)} disabled={pending}>取消</Button>
      <Button variant="danger" onclick={confirm} loading={pending} disabled={!allowed}>{confirmLabel}</Button>
    </div>
  </div>
</Modal>
