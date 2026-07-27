<script lang="ts">
  import type { AuditLog } from '$lib/api';
  import Drawer from '$lib/components/ui/Drawer.svelte';
  import Badge from '$lib/components/ui/Badge.svelte';
  import { ExternalLink } from 'lucide-svelte';

  let {
    open = $bindable(false),
    log = null,
  }: {
    open?: boolean;
    log?: AuditLog | null;
  } = $props();

  const sensitiveDetailKey = /(?:^|_)(?:password|passphrase|secret|token|credential|cookie|csrf|nonce|authorization|recovery_code|totp|private_key|api_key|code_verifier)(?:$|_)/i;

  function redactDetails(value: unknown, key = ''): unknown {
    if (key && sensitiveDetailKey.test(key)) return '[已脱敏]';
    if (Array.isArray(value)) return value.map((item) => redactDetails(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, redactDetails(childValue, childKey)]));
    }
    return value;
  }

  function targetAdminHref(entry: AuditLog | null): string | null {
    if (!entry?.target_type || !entry.target_id) return null;
    if (entry.target_type === 'user') return `/admin/users/${encodeURIComponent(entry.target_id)}`;
    if (entry.target_type === 'client') return '/admin/clients';
    if (entry.target_type === 'provider') return '/admin/providers';
    return null;
  }

  function formatDateTime(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  function resultVariant(value: string): 'success' | 'danger' | 'default' {
    return value === 'success' ? 'success' : value === 'failure' ? 'danger' : 'default';
  }

  function riskVariant(value: string): 'danger' | 'warning' | 'info' | 'default' {
    return value === 'high' || value === 'critical' ? 'danger' : value === 'medium' ? 'warning' : value === 'low' ? 'info' : 'default';
  }

  let targetHref = $derived(targetAdminHref(log));
  let detailsJSON = $derived(JSON.stringify(redactDetails(log?.details ?? {}), null, 2));
</script>

<Drawer bind:open title="审计记录详情" description={log?.event || ''} width="560px">
  {#snippet children()}
    {#if log}
      <div class="space-y-6">
        <dl class="divide-y divide-nya-divider text-body">
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4"><dt class="text-nya-text-tertiary">时间</dt><dd class="text-nya-text-primary"><time datetime={log.created_at}>{formatDateTime(log.created_at)}</time></dd></div>
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4"><dt class="text-nya-text-tertiary">事件</dt><dd class="break-all font-mono text-small text-nya-text-primary">{log.event}</dd></div>
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4">
            <dt class="text-nya-text-tertiary">操作者</dt>
            <dd class="min-w-0 text-nya-text-primary">
              <p>{log.actor_name || (log.actor_id ? '用户' : '系统')}</p>
              {#if log.actor_id}
                <a href={`/admin/users/${encodeURIComponent(log.actor_id)}`} class="mt-1 inline-flex max-w-full items-center gap-1 break-all font-mono text-small text-nya-primary hover:underline">
                  {log.actor_id}<ExternalLink size={13} aria-hidden="true" />
                  <span class="sr-only">查看操作者用户</span>
                </a>
              {/if}
            </dd>
          </div>
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4">
            <dt class="text-nya-text-tertiary">目标</dt>
            <dd class="min-w-0 text-nya-text-primary">
              <p>{log.target_type || '未指定类型'}</p>
              {#if log.target_id}<p class="mt-1 break-all font-mono text-small text-nya-text-secondary">{log.target_id}</p>{/if}
              {#if targetHref}
                <a href={targetHref} class="mt-2 inline-flex items-center gap-1 text-small font-medium text-nya-primary hover:underline">打开目标管理入口<ExternalLink size={13} aria-hidden="true" /></a>
              {/if}
            </dd>
          </div>
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4"><dt class="text-nya-text-tertiary">结果 / 风险</dt><dd class="flex flex-wrap gap-2"><Badge variant={resultVariant(log.result)}>{log.result}</Badge><Badge variant={riskVariant(log.risk_level)}>{log.risk_level}</Badge></dd></div>
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4"><dt class="text-nya-text-tertiary">IP 地址</dt><dd class="break-all font-mono text-small text-nya-text-primary">{log.ip_address || '未提供'}</dd></div>
          <div class="grid gap-1 py-3 sm:grid-cols-[112px_1fr] sm:gap-4"><dt class="text-nya-text-tertiary">User-Agent</dt><dd class="break-words text-small text-nya-text-primary">{log.user_agent || '未提供'}</dd></div>
        </dl>

        <section aria-labelledby="audit-details-heading">
          <h3 id="audit-details-heading" class="text-body-medium text-nya-text-primary">Details（已脱敏）</h3>
          <pre data-testid="audit-details-json" class="mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded-nya-sm border border-nya-border bg-nya-surface-muted p-3 font-mono text-small text-nya-text-secondary">{detailsJSON}</pre>
        </section>
      </div>
    {/if}
  {/snippet}
</Drawer>
