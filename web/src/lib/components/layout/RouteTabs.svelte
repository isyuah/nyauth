<script lang="ts">
  import { page } from '$app/stores';

  export interface RouteTab {
    href: string;
    label: string;
    exact?: boolean;
  }

  let {
    tabs = [],
    label = '页面分区',
  }: {
    tabs: RouteTab[];
    label?: string;
  } = $props();

  function isActive(tab: RouteTab): boolean {
    const pathname = $page.url.pathname;
    const tabPathname = new URL(tab.href, 'https://local.invalid').pathname;
    return pathname === tabPathname || (!tab.exact && pathname.startsWith(`${tabPathname}/`));
  }
</script>

<nav aria-label={label} class="overflow-x-auto">
  <div class="flex min-w-max gap-1 border-b border-nya-divider">
    {#each tabs as tab}
      <a
        href={tab.href}
        aria-current={isActive(tab) ? 'page' : undefined}
        class="-mb-px border-b-2 px-4 py-2.5 text-body-medium transition-colors {isActive(tab)
          ? 'border-nya-primary text-nya-primary'
          : 'border-transparent text-nya-text-secondary hover:text-nya-text-primary'}"
      >
        {tab.label}
      </a>
    {/each}
  </div>
</nav>
