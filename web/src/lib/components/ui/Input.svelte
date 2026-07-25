<script lang="ts">
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
    autocomplete?: 'current-password' | 'new-password' | 'username' | 'email' | 'off';
    oninput?: (e: Event) => void;
  } = $props();
</script>

<div class="flex flex-col gap-1.5">
  {#if label}
    <label for={id} class="text-body-medium text-nya-text-primary">
      {label}
      {#if required}<span class="text-nya-danger">*</span>{/if}
    </label>
  {/if}
  <input
    {id}
    {type}
    {placeholder}
    {disabled}
    {readonly}
    {required}
    {autocomplete}
    bind:value
    {oninput}
    class="h-[38px] w-full px-3 bg-nya-surface border rounded-nya-sm text-body text-nya-text-primary placeholder-nya-text-tertiary transition-all duration-fast
      {error ? 'border-nya-danger focus:ring-nya-danger/24' : 'border-nya-border hover:border-nya-border-strong focus:border-nya-primary focus:ring-nya-primary/24'}
      {disabled ? 'bg-nya-surface-soft text-nya-text-disabled cursor-not-allowed' : ''}
      {mono ? 'font-mono text-small' : ''}
      focus:outline-none focus:ring-2 focus:border-nya-primary"
  />
  {#if error}
    <p class="text-small text-nya-danger">{error}</p>
  {/if}
</div>
