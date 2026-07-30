<script lang="ts">
  let {
    fieldLabel,
    variables = [],
    required = [],
    oninsert,
  }: {
    fieldLabel: string;
    variables?: string[];
    required?: string[];
    oninsert: (variable: string) => void;
  } = $props();
</script>

<div class="mt-1.5 flex min-h-6 flex-wrap items-center gap-1.5" aria-label={`${fieldLabel}可用变量`}>
  {#if variables.length > 0}
    <span class="mr-0.5 text-micro text-nya-text-tertiary">插入变量</span>
    {#each variables as variable}
      <button type="button" onclick={() => oninsert(variable)} class="rounded-nya-xs border border-nya-primary-border bg-nya-primary-soft px-1.5 py-0.5 font-mono text-micro text-nya-primary hover:bg-nya-primary-softer" aria-label={`在${fieldLabel}插入变量 ${variable}`} title={required.includes(variable) ? '正文必须保留此变量' : `插入 ${variable}`}>
        {'{{'}{variable}{'}}'}{#if required.includes(variable)}<span class="ml-1 font-sans">必需</span>{/if}
      </button>
    {/each}
  {:else}
    <span class="text-micro text-nya-text-tertiary">此字段不支持变量</span>
  {/if}
</div>
