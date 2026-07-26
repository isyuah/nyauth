<script lang="ts">
  let {
    checked = $bindable(false),
    label = '',
    disabled = false,
  }: {
    checked?: boolean;
    label?: string;
    disabled?: boolean;
  } = $props();
</script>

<label class="inline-flex items-center gap-2.5 cursor-pointer {disabled ? 'opacity-50 cursor-not-allowed' : ''}">
  <button
    type="button"
    role="switch"
    {disabled}
    aria-checked={checked}
    aria-label={label || '切换选项'}
    onclick={() => !disabled && (checked = !checked)}
    class="relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors duration-fast ease-standard focus:outline-none focus:ring-2 focus:ring-nya-primary/24
      {checked ? 'bg-nya-primary' : 'bg-nya-border-strong'}"
  >
    <span
      class="pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-nya-xs transform transition duration-fast ease-standard
        {checked ? 'translate-x-4' : 'translate-x-0'}"
    ></span>
  </button>
  {#if label}
    <span class="text-body text-nya-text-primary">{label}</span>
  {/if}
</label>
