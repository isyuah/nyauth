<script lang="ts">
  import type { Snippet } from 'svelte';

  let {
    maxWidth = '700px',
    label = '授权操作',
    children,
  }: {
    maxWidth?: string;
    label?: string;
    children: Snippet;
  } = $props();
</script>

<div class="authorization-page">
  <main class="relative z-[1] w-full" style="max-width: {maxWidth};">
    <section aria-label={label} class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-popup">
      {@render children()}
    </section>
  </main>
</div>

<style>
  .authorization-page {
    min-height: 100svh;
    display: grid;
    place-items: center;
    padding: 32px 20px;
    overflow-x: clip;
    background-color: var(--nya-bg);
    background-image:
      linear-gradient(rgb(var(--nya-primary-rgb) / 0.035) 1px, transparent 1px),
      linear-gradient(90deg, rgb(var(--nya-primary-rgb) / 0.035) 1px, transparent 1px);
    background-size: 34px 34px;
  }

  @media (max-width: 640px) {
    .authorization-page {
      padding: 14px 12px;
    }
  }
</style>
