<script lang="ts">
  import { onMount } from 'svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let {
    acceptLabel,
    action = '',
    onaccept,
    ondeny,
  }: {
    acceptLabel: string;
    action?: 'accept' | 'deny' | '';
    onaccept: () => void;
    ondeny: () => void;
  } = $props();

  let actions: HTMLDivElement | null = null;
  let showQuickActions = $state(false);

  onMount(() => {
    if (!actions || typeof IntersectionObserver === 'undefined') return;
    const media = window.matchMedia('(max-height: 820px), (max-width: 760px)');
    let visibleRatio = 1;
    const update = () => (showQuickActions = media.matches && visibleRatio < 0.85);
    const observer = new IntersectionObserver(([entry]) => {
      visibleRatio = entry.intersectionRatio;
      update();
    }, { threshold: [0, 0.85, 1] });
    observer.observe(actions);
    media.addEventListener('change', update);
    return () => {
      observer.disconnect();
      media.removeEventListener('change', update);
    };
  });
</script>

<div bind:this={actions} aria-hidden={showQuickActions} inert={showQuickActions} class="mt-6 flex justify-end gap-3 border-t border-nya-divider pt-5 max-sm:[&>*]:flex-1">
  <Button variant="secondary" size="lg" onclick={ondeny} loading={action === 'deny'} disabled={action !== ''}>拒绝请求</Button>
  <Button variant="primary" size="lg" requiredCapability="auth_issuance" onclick={onaccept} loading={action === 'accept'} disabled={action !== ''}>{acceptLabel}</Button>
</div>

<div aria-hidden={!showQuickActions} inert={!showQuickActions} class="fixed inset-x-0 bottom-0 z-40 border-t border-nya-border-strong bg-nya-surface/95 px-3 py-3 backdrop-blur-sm transition duration-normal {showQuickActions ? 'visible translate-y-0 opacity-100' : 'invisible translate-y-2 opacity-0 pointer-events-none'}">
  <div class="mx-auto flex w-full max-w-[636px] justify-end gap-3 max-sm:[&>*]:flex-1">
    <Button variant="secondary" size="lg" onclick={ondeny} loading={action === 'deny'} disabled={action !== ''}>拒绝请求</Button>
    <Button variant="primary" size="lg" requiredCapability="auth_issuance" onclick={onaccept} loading={action === 'accept'} disabled={action !== ''}>{acceptLabel}</Button>
  </div>
</div>
