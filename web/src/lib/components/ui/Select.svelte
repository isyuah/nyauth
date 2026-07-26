<script lang="ts">
  import { Select } from 'bits-ui';
  import { Check, ChevronDown } from 'lucide-svelte';

  type Option = { value: string; label: string; disabled?: boolean };

  let {
    id = '',
    label = '',
    value = $bindable(''),
    options = [],
    placeholder = '请选择...',
    error = '',
    disabled = false,
  }: {
    id?: string;
    label?: string;
    value?: string;
    options: Option[];
    placeholder?: string;
    error?: string;
    disabled?: boolean;
  } = $props();

  let open = $state(false);
  let displayLabel = $derived(options.find((option) => option.value === value)?.label || placeholder);
</script>

<div class="flex flex-col gap-1.5">
  {#if label}
    <span class="text-body-medium text-nya-text-primary">{label}</span>
  {/if}

  <Select.Root type="single" bind:value bind:open items={options} {disabled}>
    <Select.Trigger
      {id}
      aria-label={label || placeholder}
      aria-invalid={error ? 'true' : undefined}
      class="flex h-[38px] w-full items-center justify-between rounded-nya-sm border bg-nya-surface px-3 text-left text-body transition-all focus:outline-none focus:ring-2 focus:ring-nya-primary/24 disabled:cursor-not-allowed disabled:bg-nya-surface-muted disabled:text-nya-text-disabled {error ? 'border-nya-danger' : 'border-nya-border-strong hover:border-nya-primary'}"
    >
      <span class="truncate {value ? 'text-nya-text-primary' : 'text-nya-text-tertiary'}">{displayLabel}</span>
      <ChevronDown size={16} class="shrink-0 text-nya-text-tertiary transition-transform {open ? 'rotate-180' : ''}" />
    </Select.Trigger>

    <Select.Portal>
      <Select.Content
        sideOffset={4}
        class="z-[80] max-h-60 min-w-[var(--bits-select-anchor-width)] overflow-hidden rounded-nya-md border border-nya-border bg-nya-surface shadow-nya-popup outline-none"
      >
        <Select.Viewport class="p-1">
          {#each options as option}
            <Select.Item
              value={option.value}
              label={option.label}
              disabled={option.disabled}
              class="flex min-h-9 cursor-default select-none items-center justify-between rounded-nya-sm px-3 text-body text-nya-text-primary outline-none data-[highlighted]:bg-nya-surface-muted data-[selected]:text-nya-primary data-[disabled]:opacity-40"
            >
              <span>{option.label}</span>
              {#if option.value === value}<Check size={14} class="text-nya-primary" />{/if}
            </Select.Item>
          {/each}
        </Select.Viewport>
      </Select.Content>
    </Select.Portal>
  </Select.Root>

  {#if error}
    <p class="text-small text-nya-danger" role="alert">{error}</p>
  {/if}
</div>
