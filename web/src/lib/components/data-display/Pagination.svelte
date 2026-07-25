<script lang="ts">
  let {
    page = $bindable(1),
    pageSize = 20,
    total = 0,
  }: {
    page?: number;
    pageSize?: number;
    total?: number;
  } = $props();

  let totalPages = $derived(Math.max(1, Math.ceil(total / pageSize)));
  let from = $derived(total === 0 ? 0 : (page - 1) * pageSize + 1);
  let to = $derived(Math.min(page * pageSize, total));
</script>

{#if total > 0}
  <div class="flex items-center justify-between px-4 py-3 text-small text-nya-text-secondary">
    <span>显示 {from}-{to}，共 {total} 条</span>
    <div class="flex items-center gap-1">
      <button
        disabled={page <= 1}
        onclick={() => page--}
        class="px-2.5 py-1 rounded-nya-xs hover:bg-nya-surface-hover disabled:opacity-40 disabled:cursor-not-allowed"
      >
        上一页
      </button>
      <span class="px-2 text-nya-text-primary">{page} / {totalPages}</span>
      <button
        disabled={page >= totalPages}
        onclick={() => page++}
        class="px-2.5 py-1 rounded-nya-xs hover:bg-nya-surface-hover disabled:opacity-40 disabled:cursor-not-allowed"
      >
        下一页
      </button>
    </div>
  </div>
{/if}
