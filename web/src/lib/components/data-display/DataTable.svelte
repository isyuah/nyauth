<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    columns = [],
    data = [],
    emptyText = '暂无数据',
    onRowClick,
    actions,
  }: {
    columns: Array<{ key: string; label: string; width?: string; mono?: boolean; render?: Snippet<[any]> }>;
    data: any[];
    emptyText?: string;
    onRowClick?: (row: any) => void;
    actions?: Snippet<[any]>;
  } = $props();
</script>

<div class="overflow-x-auto">
  <table class="w-full">
    <thead>
      <tr class="border-b border-nya-divider">
        {#each columns as col}
          <th
            class="text-left px-4 h-[42px] text-micro font-medium text-nya-text-tertiary uppercase tracking-wider"
            style={col.width ? `width: ${col.width}` : ''}
          >
            {col.label}
          </th>
        {/each}
        {#if actions}
          <th class="text-right px-4 h-[42px] text-micro font-medium text-nya-text-tertiary w-20">操作</th>
        {/if}
      </tr>
    </thead>
    <tbody>
      {#each data as row, i}
        <tr
          class="border-b border-nya-divider/50 hover:bg-nya-surface-hover transition-colors duration-fast {onRowClick ? 'cursor-pointer' : ''}"
          onclick={() => onRowClick?.(row)}
        >
          {#each columns as col}
            <td class="px-4 h-12 text-body text-nya-text-primary {col.mono ? 'font-mono text-small' : ''}">
              {row[col.key] ?? '-'}
            </td>
          {/each}
          {#if actions}
            <td class="px-4 h-12 text-right">
              {@render actions(row)}
            </td>
          {/if}
        </tr>
      {/each}
    </tbody>
  </table>

  {#if data.length === 0}
    <div class="py-12 text-center text-body text-nya-text-tertiary">{emptyText}</div>
  {/if}
</div>
