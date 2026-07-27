<script lang="ts">
  import FormField from './FormField.svelte';

  let {
    label = '',
    placeholder = '',
    value = $bindable(''),
    type = 'text',
    error = '',
    disabled = false,
    readonly = false,
    mono = false,
    required = false,
    id = '',
    autocomplete,
    inputmode,
    maxlength,
    oninput,
  }: {
    label?: string;
    placeholder?: string;
    value?: string;
    type?: string;
    error?: string;
    disabled?: boolean;
    readonly?: boolean;
    mono?: boolean;
    required?: boolean;
    id?: string;
    autocomplete?: 'current-password' | 'new-password' | 'username' | 'username webauthn' | 'email' | 'one-time-code' | 'off';
    inputmode?: 'text' | 'numeric' | 'email' | 'url' | 'search' | 'tel' | 'decimal' | 'none';
    maxlength?: number;
    oninput?: (e: Event) => void;
  } = $props();

  const componentId = $props.id();
  let resolvedId = $derived(id || `${componentId}-input`);
  let describedBy = $derived(error ? `${resolvedId}-error` : undefined);
</script>

<FormField id={resolvedId} {label} {required} {error}>
  {#snippet children()}
  <input
    id={resolvedId}
    {type}
    {placeholder}
    {disabled}
    {readonly}
    {required}
    {autocomplete}
    {inputmode}
    {maxlength}
    aria-invalid={error ? 'true' : undefined}
    aria-describedby={describedBy}
    bind:value
    {oninput}
    class="h-[38px] w-full px-3 bg-nya-surface border rounded-nya-sm text-body text-nya-text-primary placeholder-nya-text-tertiary transition-all duration-fast
      {error ? 'border-nya-danger focus:ring-nya-danger/24' : 'border-nya-border hover:border-nya-border-strong focus:border-nya-primary focus:ring-nya-primary/24'}
      {disabled ? 'bg-nya-surface-soft text-nya-text-disabled cursor-not-allowed' : ''}
      {mono ? 'font-mono text-small' : ''}
      focus:outline-none focus:ring-2 focus:border-nya-primary"
  />
  {/snippet}
</FormField>
