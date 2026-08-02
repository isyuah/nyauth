<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { ServiceCapability } from '$lib/api';
  import { capabilityPauseReason, isCapabilityPaused, serviceStatusStore } from '$lib/service-control';

  let {
    variant = 'primary',
    size = 'md',
    disabled = false,
    loading = false,
    type = 'button',
    onclick,
    ariaLabel,
    title,
    requiredCapability,
    fullWidth = false,
    children,
  }: {
    variant?: 'primary' | 'secondary' | 'soft' | 'ghost' | 'danger';
    size?: 'sm' | 'md' | 'lg';
    disabled?: boolean;
    loading?: boolean;
    type?: 'button' | 'submit' | 'reset';
    onclick?: (e: MouseEvent) => void;
    ariaLabel?: string;
    title?: string;
    requiredCapability?: ServiceCapability;
    fullWidth?: boolean;
    children: Snippet;
  } = $props();

  let capabilityBlocked = $derived(requiredCapability
    ? isCapabilityPaused($serviceStatusStore.value, requiredCapability)
    : false);
  let disabledReason = $derived(requiredCapability
    ? capabilityPauseReason($serviceStatusStore.value, requiredCapability)
    : '');

  const styles: Record<string, string> = {
    primary: 'background: var(--nya-primary); color: var(--nya-primary-contrast); box-shadow: 0 5px 12px rgb(var(--nya-primary-rgb) / 0.20);',
    secondary: 'background: var(--nya-surface); color: var(--nya-text-primary); border: 1px solid var(--nya-border-strong);',
    soft: 'background: var(--nya-primary-soft); color: var(--nya-primary);',
    ghost: 'background: transparent; color: var(--nya-text-secondary);',
    danger: 'background: var(--nya-danger); color: #fff;',
  };

  const heights: Record<string, string> = { sm: '32px', md: '38px', lg: '44px' };
  const paddings: Record<string, string> = { sm: '0 12px', md: '0 16px', lg: '0 20px' };
  const fontSizes: Record<string, string> = { sm: '12px', md: '14px', lg: '14px' };
</script>

<button
  {type}
  disabled={disabled || loading || capabilityBlocked}
  {onclick}
  aria-label={ariaLabel}
  aria-busy={loading}
  title={capabilityBlocked ? disabledReason : title}
  class:w-full={fullWidth}
  style="{styles[variant]}; height: {heights[size]}; padding: {paddings[size]}; font-size: {fontSizes[size]}; font-weight: 550; border-radius: 9px; display: inline-flex; align-items: center; justify-content: center; gap: 8px; cursor: {disabled || loading || capabilityBlocked ? 'not-allowed' : 'pointer'}; opacity: {disabled || loading || capabilityBlocked ? 0.5 : 1}; transition: all 0.15s;"
>
  {#if loading}
    <svg class="animate-spin" style="width: 16px; height: 16px;" viewBox="0 0 24 24" fill="none">
      <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
      <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
    </svg>
  {/if}
  {@render children()}
</button>
