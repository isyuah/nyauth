<script lang="ts">
  import { Tabs } from 'bits-ui';

  let {
    tabs = [],
    active = $bindable(''),
  }: {
    tabs: Array<{ value: string; label: string; disabled?: boolean }>;
    active?: string;
  } = $props();

  $effect(() => {
    if (!active && tabs.length > 0) active = tabs[0].value;
  });
</script>

<Tabs.Root value={active} onValueChange={(value) => (active = value)}>
  <Tabs.List class="flex gap-1 border-b border-nya-divider" aria-label="页面分区">
    {#each tabs as tab}
      <Tabs.Trigger
        value={tab.value}
        disabled={tab.disabled}
        class="-mb-px border-b-2 border-transparent px-4 py-2.5 text-body-medium text-nya-text-secondary transition-colors hover:text-nya-text-primary data-[state=active]:border-nya-primary data-[state=active]:text-nya-primary"
      >
        {tab.label}
      </Tabs.Trigger>
    {/each}
  </Tabs.List>
</Tabs.Root>
