<script lang="ts">
  import { ChevronDown, Check } from 'lucide-svelte';
  import { fly } from 'svelte/transition';

  let {
    label = '',
    value = $bindable(''),
    options = [],
    placeholder = '请选择...',
    error = '',
    disabled = false,
  }: {
    label?: string;
    value?: string;
    options: Array<{ value: string; label: string }>;
    placeholder?: string;
    error?: string;
    disabled?: boolean;
  } = $props();

  let open = $state(false);
  let containerEl: HTMLDivElement | undefined = $state();

  function select(val: string) {
    value = val;
    open = false;
  }

  function handleClickOutside(e: MouseEvent) {
    if (containerEl && !containerEl.contains(e.target as Node)) {
      open = false;
    }
  }

  let displayLabel = $derived(options.find(o => o.value === value)?.label || placeholder);
</script>

<svelte:window onclick={handleClickOutside} />

<div class="relative" bind:this={containerEl}>
  {#if label}
    <label class="block mb-1.5" style="font-size: 14px; font-weight: 550; color: var(--nya-text-primary);">{label}</label>
  {/if}

  <button
    type="button"
    {disabled}
    onclick={(e) => { e.stopPropagation(); open = !open; }}
    class="relative flex items-center justify-between w-full text-left transition-all"
    style="height: 38px; padding: 0 12px; border: 1px solid {error ? 'var(--nya-danger)' : open ? 'var(--nya-primary)' : 'var(--nya-border-strong)'}; border-radius: 9px; background: {disabled ? 'var(--nya-surface-muted)' : 'var(--nya-surface)'}; font-size: 14px; color: {value ? 'var(--nya-text-primary)' : 'var(--nya-text-tertiary)'}; box-shadow: {open ? '0 0 0 3px rgba(124, 92, 255, 0.13)' : 'none'};"
  >
    <span class="truncate">{displayLabel}</span>
    <ChevronDown size={16} class="shrink-0 transition-transform duration-150 {open ? 'rotate-180' : ''}" style="color: var(--nya-text-tertiary);" />
  </button>

  {#if open}
    <div
      class="absolute left-0 right-0 bg-[var(--nya-surface)] border border-[var(--nya-border)] overflow-auto z-50"
      style="top: calc(100% + 4px); border-radius: var(--nya-radius-md); box-shadow: var(--nya-shadow-popup); max-height: 240px;"
      transition:fly={{ y: -8, duration: 150 }}
    >
      {#each options as opt}
        <button
          type="button"
          onclick={() => select(opt.value)}
          class="w-full flex items-center justify-between transition-colors"
          style="height: 36px; padding: 0 12px; font-size: 14px; text-align: left; color: {opt.value === value ? 'var(--nya-primary)' : 'var(--nya-text-primary)'}; background: {opt.value === value ? 'var(--nya-primary-soft)' : 'transparent'};"
          onmouseenter={(e) => (e.currentTarget.style.background = opt.value === value ? 'var(--nya-primary-soft)' : 'var(--nya-surface-hover)')}
          onmouseleave={(e) => (e.currentTarget.style.background = opt.value === value ? 'var(--nya-primary-soft)' : 'transparent')}
        >
          <span>{opt.label}</span>
          {#if opt.value === value}
            <Check size={14} style="color: var(--nya-primary);" />
          {/if}
        </button>
      {/each}
    </div>
  {/if}

  {#if error}
    <p style="font-size: 12px; color: var(--nya-danger); margin-top: 4px;">{error}</p>
  {/if}
</div>
