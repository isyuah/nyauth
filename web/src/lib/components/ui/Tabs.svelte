<script lang="ts">
  let {
    tabs = [],
    active = $bindable(''),
  }: {
    tabs: Array<{ value: string; label: string }>;
    active?: string;
  } = $props();

  if (!active && tabs.length > 0) active = tabs[0].value;
</script>

<div class="flex border-b border-nya-divider gap-1">
  {#each tabs as tab}
    <button
      onclick={() => (active = tab.value)}
      class="px-4 py-2.5 text-body-medium transition-colors duration-fast border-b-2 -mb-px
        {active === tab.value
          ? 'text-nya-primary border-nya-primary'
          : 'text-nya-text-secondary border-transparent hover:text-nya-text-primary hover:border-nya-border'}"
    >
      {tab.label}
    </button>
  {/each}
</div>
