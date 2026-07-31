<script lang="ts">
  import { onMount } from 'svelte';
  import type { HumanVerificationChallenge, HumanVerificationProof } from '$lib/api';
  import {
    loadTurnstile,
    turnstilePresentation,
    type TurnstileAPI,
    type TurnstileWidgetMode,
  } from '$lib/turnstile';

  interface Props {
    challenge: HumanVerificationChallenge;
    proof: HumanVerificationProof | null;
    onerror?: (message: string) => void;
  }

  let { challenge, proof = $bindable(), onerror }: Props = $props();
  let container: HTMLDivElement;
  let status = $state('正在加载人机验证…');
  let widgetId: string | null = null;
  let api: TurnstileAPI | null = null;
  let mounted = true;
  let widgetMode = $derived((challenge.widget_mode ?? 'managed') as TurnstileWidgetMode);
  let presentation = $derived(turnstilePresentation(widgetMode));

  function clearProof(message: string) {
    proof = null;
    status = message;
  }

  onMount(() => {
    mounted = true;
    void (async () => {
      if (challenge.provider !== 'turnstile' || !challenge.site_key) {
        const message = '人机验证配置不可用';
        clearProof(message);
        onerror?.(message);
        return;
      }
      try {
        api = await loadTurnstile();
        if (!mounted) return;
        widgetId = api.render(container, {
          sitekey: challenge.site_key,
          action: challenge.action,
          theme: 'auto',
          size: 'flexible',
          appearance: presentation.appearance,
          callback: (token) => {
            if (!mounted) return;
            proof = { token, idempotency_key: crypto.randomUUID() };
            status = '人机验证已完成';
          },
          'expired-callback': () => clearProof('验证已过期，请重新完成'),
          'timeout-callback': () => clearProof('验证超时，请重新完成'),
          'error-callback': () => {
            const message = '人机验证加载失败，请稍后重试';
            clearProof(message);
            onerror?.(message);
            return true;
          },
        });
        status = widgetMode === 'non-interactive' ? '正在进行人机验证…' : '正在后台进行人机验证…';
      } catch (cause) {
        if (!mounted) return;
        const message = cause instanceof Error ? cause.message : '人机验证加载失败';
        clearProof(message);
        onerror?.(message);
      }
    })();
    return () => {
      mounted = false;
      proof = null;
      if (api && widgetId !== null) api.remove(widgetId);
      widgetId = null;
    };
  });
</script>

<div
  class:human-verification-widget--reserved={presentation.reserveSpace}
  class="human-verification-widget"
  data-testid="human-verification-widget"
  data-widget-mode={widgetMode}
>
  <div bind:this={container}></div>
  <p class:sr-only={!presentation.showProgress} class="mt-1.5 text-small text-nya-text-tertiary" aria-live="polite">{status}</p>
</div>

<style>
  .human-verification-widget--reserved {
    min-height: 72px;
  }

  .human-verification-widget { width: 100%; }
</style>
