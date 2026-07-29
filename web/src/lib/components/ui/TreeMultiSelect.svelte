<script lang="ts">
  import { tick } from 'svelte';
  import { ChevronDown, Search, X } from 'lucide-svelte';

  let {
    id = '',
    label = '',
    values = $bindable<string[]>([]),
    options = [],
    placeholder = '搜索并选择…',
    disabled = false,
  }: {
    id?: string;
    label?: string;
    values?: string[];
    options: string[];
    placeholder?: string;
    disabled?: boolean;
  } = $props();

  let root: HTMLDivElement;
  let input: HTMLInputElement;
  let tree = $state<HTMLDivElement | null>(null);
  let open = $state(false);
  let search = $state('');
  let filtered = $derived(options.filter((option) => option.toLowerCase().includes(search.trim().toLowerCase())));
  let groups = $derived(groupOptions(filtered));

  function groupOptions(items: string[]) {
    const grouped = new Map<string, string[]>();
    for (const item of items) {
      const separator = item.indexOf('.');
      const group = separator > 0 ? item.slice(0, separator) : '其他';
      grouped.set(group, [...(grouped.get(group) || []), item]);
    }
    return Array.from(grouped, ([name, entries]) => ({ name, entries }));
  }

  function selected(value: string): boolean {
    return values.includes(value);
  }

  function toggle(value: string) {
    values = selected(value) ? values.filter((item) => item !== value) : [...values, value];
  }

  function toggleGroup(entries: string[]) {
    const allSelected = entries.every(selected);
    values = allSelected
      ? values.filter((item) => !entries.includes(item))
      : Array.from(new Set([...values, ...entries]));
  }

  function handleWindowPointerDown(event: PointerEvent) {
    if (open && root && !root.contains(event.target as Node)) open = false;
  }

  function treeCheckboxes(): HTMLInputElement[] {
    return tree ? Array.from(tree.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')) : [];
  }

  async function openAndFocusFirst() {
    open = true;
    await tick();
    treeCheckboxes()[0]?.focus();
  }

  function handleInputKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      open = false;
      input.blur();
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      void openAndFocusFirst();
    }
  }

  function handleTreeKeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.stopPropagation();
      open = false;
      input.focus();
      return;
    }
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const checkboxes = treeCheckboxes();
    const index = checkboxes.indexOf(event.target as HTMLInputElement);
    if (index < 0) return;
    event.preventDefault();
    if (event.key === 'ArrowDown') checkboxes[index + 1]?.focus();
    else if (index === 0) input.focus();
    else checkboxes[index - 1]?.focus();
  }
</script>

<svelte:window onpointerdown={handleWindowPointerDown} />

<div class="relative flex flex-col gap-1.5" bind:this={root}>
  {#if label}<label for={id} class="text-body-medium text-nya-text-primary">{label}</label>{/if}
  <div class="flex min-h-[38px] w-full flex-wrap items-center gap-1.5 rounded-nya-sm border border-nya-border-strong bg-nya-surface px-2 py-1 transition-all focus-within:border-nya-primary focus-within:ring-2 focus-within:ring-nya-primary/24">
    {#each values as value}
      <span class="inline-flex max-w-full items-center gap-1 rounded-nya-sm bg-nya-primary-soft px-1.5 py-0.5 font-mono text-micro text-nya-primary">
        <span class="truncate">{value}</span>
        <button type="button" class="shrink-0" aria-label={`移除事件 ${value}`} onclick={() => toggle(value)}><X size={12} /></button>
      </span>
    {/each}
    <div class="flex min-w-[8rem] flex-1 items-center gap-1.5">
      <Search size={14} class="shrink-0 text-nya-text-tertiary" />
      <input
        {id}
        bind:this={input}
        bind:value={search}
        {disabled}
        autocomplete="off"
        data-bwignore="true"
        data-1p-ignore="true"
        data-lpignore="true"
        role="combobox"
        aria-haspopup="dialog"
        aria-autocomplete="list"
        placeholder={values.length > 0 ? '继续搜索…' : placeholder}
        aria-expanded={open}
        aria-controls={`${id}-tree`}
        onfocus={() => (open = true)}
        oninput={() => (open = true)}
        onkeydown={handleInputKeydown}
        class="h-7 min-w-0 flex-1 bg-transparent text-body text-nya-text-primary placeholder-nya-text-tertiary focus:outline-none"
      />
      <button type="button" aria-label={open ? '收起事件列表' : '展开事件列表'} disabled={disabled} onclick={() => (open = !open)} class="text-nya-text-tertiary"><ChevronDown size={15} class={open ? 'rotate-180' : ''} /></button>
    </div>
  </div>

  {#if open && !disabled}
    <div id={`${id}-tree`} bind:this={tree} role="group" class="absolute top-full z-[70] mt-1 max-h-80 w-full min-w-72 overflow-y-auto rounded-nya-md border border-nya-border bg-nya-surface p-1.5 shadow-nya-popup" aria-label={`${label}选项`}>
      {#if groups.length === 0}
        <p class="px-3 py-4 text-center text-small text-nya-text-tertiary">没有匹配的事件</p>
      {:else}
        {#each groups as group}
          <section aria-label={`${group.name} 事件组`}>
            <div class="flex items-center justify-between rounded-nya-sm px-2 py-1.5 text-small font-semibold text-nya-text-secondary">
              <span>{group.name}</span>
              <label class="flex items-center gap-1.5 font-normal">
                <input type="checkbox" checked={group.entries.every(selected)} onchange={() => toggleGroup(group.entries)} onkeydown={handleTreeKeydown} />
                全选
              </label>
            </div>
            <div class="ml-2 border-l border-nya-divider pl-2">
              {#each group.entries as option}
                <label class="flex cursor-pointer items-center gap-2 rounded-nya-sm px-2 py-1.5 font-mono text-small text-nya-text-primary hover:bg-nya-surface-muted">
                  <input type="checkbox" checked={selected(option)} onchange={() => toggle(option)} onkeydown={handleTreeKeydown} />
                  <span class="truncate" title={option}>{option}</span>
                </label>
              {/each}
            </div>
          </section>
        {/each}
      {/if}
    </div>
  {/if}
</div>
