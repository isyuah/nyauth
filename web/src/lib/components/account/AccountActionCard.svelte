<script lang="ts">
  import type { Snippet } from 'svelte';
  import BrandLogo from '$lib/components/layout/BrandLogo.svelte';

  let {
    title,
    description,
    children,
  }: {
    title: string;
    description: string;
    children: Snippet;
  } = $props();
</script>

<main class="account-action-page flex min-h-screen items-center justify-center px-4 py-10">
  <div class="w-full max-w-[440px]">
    <a href="/" class="mx-auto mb-6 flex w-fit flex-col items-center">
		<BrandLogo size={56} showName />
    </a>
    <section class="rounded-nya-lg border border-nya-border bg-nya-surface p-7 shadow-nya-card">
      <header class="mb-6 text-center"><h1 class="text-xl font-bold text-nya-text-primary">{title}</h1><p class="mt-2 text-body text-nya-text-secondary">{description}</p></header>
      {@render children()}
    </section>
  </div>
</main>

<style>
  .account-action-page {
    background-color: var(--nya-bg);
    background-image:
      linear-gradient(rgb(var(--nya-primary-rgb) / 0.035) 1px, transparent 1px),
      linear-gradient(90deg, rgb(var(--nya-primary-rgb) / 0.035) 1px, transparent 1px);
    background-size: 34px 34px;
  }
</style>
