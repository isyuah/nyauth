<script lang="ts">
  import type { Snippet } from 'svelte';

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

<main class="flex min-h-screen items-center justify-center bg-gradient-to-br from-[#f8f5ff] via-[#fffaff] to-[#edf8ff] px-4 py-10">
  <div class="w-full max-w-[440px]">
    <a href="/" class="mx-auto mb-6 block w-fit bg-gradient-to-br from-[#8A6CFF] via-[#C28BFF] to-[#FF9BCB] bg-clip-text text-[38px] font-bold leading-none text-transparent">Nya</a>
    <section class="rounded-nya-lg border border-nya-border bg-nya-surface p-7 shadow-nya-card">
      <header class="mb-6 text-center"><h1 class="text-xl font-bold text-nya-text-primary">{title}</h1><p class="mt-2 text-body text-nya-text-secondary">{description}</p></header>
      {@render children()}
    </section>
  </div>
</main>
