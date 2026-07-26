<script lang="ts">
  import type { Snippet } from 'svelte';
  import { TriangleAlert } from 'lucide-svelte';

  let {
    title = '危险操作',
    description,
    children,
  }: {
    title?: string;
    description: string;
    children: Snippet;
  } = $props();
</script>

<section class="border-t border-nya-danger/30 pt-4" aria-labelledby="danger-zone-title">
  <div class="mb-3 flex items-start gap-2.5">
    <TriangleAlert size={18} class="mt-0.5 shrink-0 text-nya-danger" aria-hidden="true" />
    <div>
      <h3 id="danger-zone-title" class="font-semibold text-nya-danger">{title}</h3>
      <p class="mt-1 text-small text-nya-text-secondary">{description}</p>
    </div>
  </div>
  {@render children()}
</section>
