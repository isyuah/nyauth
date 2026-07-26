<script lang="ts" generics="T extends Record<string, unknown>">
  import type { Snippet } from 'svelte';

  interface Column<Row extends Record<string, unknown>> {
    key: keyof Row & string;
    label: string;
    width?: string;
    mono?: boolean;
    render?: Snippet<[Row]>;
  }

  let {
    columns = [],
    data = [],
    emptyText = '暂无数据',
    onRowClick,
    actions,
  }: {
    columns: Column<T>[];
    data: T[];
    emptyText?: string;
    onRowClick?: (row: T) => void;
    actions?: Snippet<[T]>;
  } = $props();

  function activateRow(event: KeyboardEvent, row: T) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onRowClick?.(row);
    }
  }
</script>

<div class="overflow-x-auto">
  <table class="w-full">
    <thead>
      <tr class="border-b border-nya-divider">
        {#each columns as col}
          <th
            scope="col"
            class="h-[42px] px-4 text-left text-micro font-medium uppercase tracking-wider text-nya-text-tertiary"
            style={col.width ? `width: ${col.width}` : ''}
          >
            {col.label}
          </th>
        {/each}
        {#if actions}
          <th scope="col" class="h-[42px] w-20 px-4 text-right text-micro font-medium text-nya-text-tertiary">操作</th>
        {/if}
      </tr>
    </thead>
    <tbody>
      {#each data as row}
        <tr
          class="border-b border-nya-divider/50 transition-colors hover:bg-nya-surface-muted {onRowClick ? 'cursor-pointer' : ''}"
          role={onRowClick ? 'button' : undefined}
          tabindex={onRowClick ? 0 : undefined}
          onclick={() => onRowClick?.(row)}
          onkeydown={(event) => activateRow(event, row)}
        >
          {#each columns as col}
            <td class="h-12 px-4 text-body text-nya-text-primary {col.mono ? 'font-mono text-small' : ''}">
              {#if col.render}
                {@render col.render(row)}
              {:else}
                {String(row[col.key] ?? '-')}
              {/if}
            </td>
          {/each}
          {#if actions}
            <td class="h-12 px-4 text-right">{@render actions(row)}</td>
          {/if}
        </tr>
      {/each}
    </tbody>
  </table>

  {#if data.length === 0}
    <div class="py-12 text-center text-body text-nya-text-tertiary">{emptyText}</div>
  {/if}
</div>
