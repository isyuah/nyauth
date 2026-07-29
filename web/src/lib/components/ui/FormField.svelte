<script lang="ts">
  import type { Snippet } from 'svelte';
  import FieldHelp from './FieldHelp.svelte';

  let {
    id,
    label = '',
    required = false,
    error = '',
    hint = '',
    help = '',
    children,
  }: {
    id: string;
    label?: string;
    required?: boolean;
    error?: string;
    hint?: string;
    help?: string;
    children: Snippet;
  } = $props();
</script>

<div class="flex flex-col gap-1.5">
  {#if label}
    <div class="flex items-center gap-1.5">
      <label for={id} class="text-body-medium text-nya-text-primary">
        {label}
        {#if required}<span class="text-nya-danger" aria-hidden="true">*</span>{/if}
      </label>
      {#if help}<FieldHelp id={`${id}-help`} text={help} label={`查看“${label}”说明`} />{/if}
    </div>
  {/if}
  {@render children()}
  {#if error}
    <p id={`${id}-error`} class="text-small text-nya-danger" role="alert">{error}</p>
  {:else if hint}
    <p id={`${id}-hint`} class="text-small text-nya-text-tertiary">{hint}</p>
  {/if}
</div>
