<script lang="ts">
  import { onMount } from 'svelte';
  import type { ConsentRequest } from '$lib/api';
  import { ExternalLink, Info } from 'lucide-svelte';

  let { consent, deviceFlow = false }: { consent: ConsentRequest; deviceFlow?: boolean } = $props();
  let open = $state(false);
  let container: HTMLDivElement | null = null;

  onMount(() => {
    const closeOutside = (event: PointerEvent) => {
      if (!open || !container || !(event.target instanceof Node) || container.contains(event.target)) return;
      open = false;
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') open = false;
    };
    document.addEventListener('pointerdown', closeOutside);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOutside);
      document.removeEventListener('keydown', closeOnEscape);
    };
  });
</script>

<div class="relative" bind:this={container}>
  <button
    type="button"
    class="inline-flex h-9 items-center gap-1.5 rounded-nya-sm border border-nya-border bg-nya-surface-soft px-3 text-small font-semibold text-nya-text-secondary transition-colors hover:border-nya-primary-border hover:bg-nya-primary-soft hover:text-nya-primary"
    aria-expanded={open}
    aria-controls="authorization-technical-information"
    onclick={() => (open = !open)}
  >
    <Info size={15} /> 应用技术信息
  </button>

  <div
    id="authorization-technical-information"
    aria-hidden={!open}
    class="absolute inset-x-0 top-[calc(100%+7px)] z-20 origin-top rounded-nya-md border border-nya-border bg-nya-surface p-4 shadow-nya-popup transition duration-normal {open ? 'visible translate-y-0 scale-100 opacity-100' : 'invisible -translate-y-1 scale-[0.985] opacity-0 pointer-events-none'}"
  >
    <dl class="grid grid-cols-[104px_minmax(0,1fr)] gap-x-3 gap-y-2 text-small">
      <dt class="text-nya-text-tertiary">Client ID</dt><dd class="break-all font-mono text-nya-text-primary">{consent.client_id}</dd>
      <dt class="text-nya-text-tertiary">注册来源</dt><dd class="text-nya-text-primary">{consent.publisher_type === 'system_managed' ? '系统管理员配置' : '用户注册应用'}</dd>
      <dt class="text-nya-text-tertiary">发布者状态</dt><dd class="text-nya-text-primary">{consent.verification_status === 'verified' ? '已由管理员审核' : consent.verification_status === 'not_applicable' ? '系统管理' : '尚未验证'}</dd>
      <dt class="text-nya-text-tertiary">{deviceFlow ? '授权方式' : '回调来源'}</dt><dd class="break-all text-nya-text-primary {deviceFlow ? '' : 'font-mono'}">{deviceFlow ? '设备代码授权，不会跳转至第三方回调地址' : consent.redirect_origin || '不可用'}</dd>
    </dl>
    {#if consent.homepage_uri || consent.privacy_policy_uri || consent.terms_of_service_uri}
      <nav aria-label="应用信息链接" class="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-small">
        {#if consent.homepage_uri}<a href={consent.homepage_uri} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-nya-primary hover:underline"><ExternalLink size={13} /> 应用主页</a>{/if}
        {#if consent.privacy_policy_uri}<a href={consent.privacy_policy_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">隐私政策</a>{/if}
        {#if consent.terms_of_service_uri}<a href={consent.terms_of_service_uri} target="_blank" rel="noopener noreferrer" class="text-nya-primary hover:underline">服务条款</a>{/if}
      </nav>
    {/if}
  </div>
</div>
