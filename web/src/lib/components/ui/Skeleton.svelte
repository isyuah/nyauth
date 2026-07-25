<script lang="ts">
  let { lines = 3, width = '100%' }: { lines?: number; width?: string } = $props();
</script>

<div class="space-y-3">
  {#each Array(lines) as _, i}
    <div
      class="h-4 rounded-nya-sm bg-nya-surface-soft animate-pulse"
      style="width: {i === lines - 1 ? '60%' : width}"
    ></div>
  {/each}
</div>
