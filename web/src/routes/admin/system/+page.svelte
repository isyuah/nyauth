<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type SystemStatus } from '$lib/api';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import { Database, HardDrive, KeyRound, Mail, Network, Server } from 'lucide-svelte';

  let systemStatus = $state<SystemStatus | null>(null);
  let loading = $state(true);
  let error = $state('');

  async function loadSystemStatus() {
    loading = true;
    error = '';
    try {
      systemStatus = await api.admin.getSystemStatus();
    } catch (cause) {
      systemStatus = null;
      error = cause instanceof Error ? cause.message : '系统状态加载失败';
    } finally {
      loading = false;
    }
  }

  function formatLatency(value: number): string {
    return Number.isFinite(value) ? `${value.toLocaleString()} ms` : '不可用';
  }

  function formatDateTime(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  onMount(loadSystemStatus);
</script>

<svelte:head><title>系统状态 - Nya</title></svelte:head>

<PageHeader title="系统状态" description="查看当前实例、依赖服务和持久化后端的运行状态" />

<ResourceState
  {loading}
  {error}
  empty={!systemStatus}
  emptyTitle="暂无系统状态"
  emptyDescription="服务尚未返回可展示的运行状态。"
  onretry={loadSystemStatus}
>
  {#snippet children()}
    {#if systemStatus}
      <div class="space-y-4">
        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="flex flex-wrap items-start justify-between gap-4">
            <div class="flex items-start gap-3">
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><Server size={19} /></span>
              <div><h2 class="text-card-title text-nya-text-primary">Nyauth 服务</h2><p class="mt-1 text-body text-nya-text-secondary">当前实例的总体运行状态</p></div>
            </div>
            <div class="flex items-center gap-3"><span class="font-mono text-small text-nya-text-secondary">{systemStatus.version}</span><StatusBadge status={systemStatus.status} /></div>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><Database size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">数据库基线</h2></div>
          <dl class="grid gap-4 sm:grid-cols-3">
            <div class="rounded-nya-md bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">Schema 状态</dt><dd class="mt-2"><StatusBadge status={systemStatus.schema.status} /></dd></div>
            <div class="rounded-nya-md bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">当前版本</dt><dd class="mt-2 font-mono text-body-medium text-nya-text-primary">{systemStatus.schema.version}</dd></div>
            <div class="rounded-nya-md bg-nya-surface-muted p-4"><dt class="text-small text-nya-text-tertiary">要求版本</dt><dd class="mt-2 font-mono text-body-medium text-nya-text-primary">{systemStatus.schema.required_version}</dd></div>
          </dl>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><Network size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">依赖与存储</h2></div>
          <div class="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3"><h3 class="text-body-medium font-semibold text-nya-text-primary">PostgreSQL</h3><StatusBadge status={systemStatus.services.postgresql.status} /></div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p><p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.postgresql.latency_ms)}</p>
            </article>
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3"><h3 class="text-body-medium font-semibold text-nya-text-primary">Redis</h3><StatusBadge status={systemStatus.services.redis.status} /></div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p><p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.redis.latency_ms)}</p>
            </article>
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3"><h3 class="text-body-medium font-semibold text-nya-text-primary">JWK</h3><StatusBadge status={systemStatus.services.jwk.status} /></div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p><p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.jwk.latency_ms)}</p>
            </article>
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3"><h3 class="text-body-medium font-semibold text-nya-text-primary">Provider 快照</h3><StatusBadge status={systemStatus.services.providers.status} /></div>
              <dl class="mt-3 grid grid-cols-2 gap-3 text-small"><div><dt class="text-nya-text-tertiary">响应延迟</dt><dd class="mt-1 font-mono text-nya-text-primary">{formatLatency(systemStatus.services.providers.latency_ms)}</dd></div><div><dt class="text-nya-text-tertiary">快照修订</dt><dd class="mt-1 font-mono text-nya-text-primary">{systemStatus.services.providers.snapshot_revision}</dd></div></dl>
            </article>
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3"><div class="flex items-center gap-2"><Mail size={16} class="text-nya-primary" /><h3 class="text-body-medium font-semibold text-nya-text-primary">SMTP 邮件</h3></div><StatusBadge status={systemStatus.services.mail.status} /></div>
              <dl class="mt-3 grid grid-cols-2 gap-3 text-small"><div><dt class="text-nya-text-tertiary">运行模式</dt><dd class="mt-1 text-nya-text-primary">{systemStatus.services.mail.mode === 'fallback' ? '环境回退' : systemStatus.services.mail.mode === 'active' ? '动态配置' : '已禁用'}</dd></div><div><dt class="text-nya-text-tertiary">熔断状态</dt><dd class="mt-1 text-nya-text-primary">{systemStatus.services.mail.circuit_state === 'open' ? '已打开' : '正常'}</dd></div></dl>
            </article>
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3"><div class="flex items-center gap-2"><HardDrive size={16} class="text-nya-primary" /><h3 class="text-body-medium font-semibold text-nya-text-primary">头像媒体</h3></div><StatusBadge status={systemStatus.services.media.status} /></div>
              <dl class="mt-3 grid grid-cols-2 gap-3 text-small"><div><dt class="text-nya-text-tertiary">存储后端</dt><dd class="mt-1 text-nya-text-primary">{systemStatus.services.media.backend === 's3' ? '私有 S3' : '本地目录'}</dd></div><div><dt class="text-nya-text-tertiary">配置状态</dt><dd class="mt-1 text-nya-text-primary">{systemStatus.services.media.configured ? '已配置' : '未配置'}</dd></div></dl>
              {#if systemStatus.services.media.last_error_at}<p class="mt-3 text-small text-nya-text-tertiary">最近存储错误：{formatDateTime(systemStatus.services.media.last_error_at)}</p>{/if}
            </article>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2"><KeyRound size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">活动签名密钥</h2></div>
          {#if systemStatus.active_signing_key}
            <dl class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <div class="min-w-0"><dt class="text-small text-nya-text-tertiary">Key ID</dt><dd class="mt-1 truncate font-mono text-body-medium text-nya-text-primary" title={systemStatus.active_signing_key.kid}>{systemStatus.active_signing_key.kid}</dd></div>
              <div><dt class="text-small text-nya-text-tertiary">状态</dt><dd class="mt-2"><StatusBadge status={systemStatus.active_signing_key.status} /></dd></div>
              <div><dt class="text-small text-nya-text-tertiary">开始签名</dt><dd class="mt-1 text-body-medium text-nya-text-primary"><time datetime={systemStatus.active_signing_key.signing_started_at}>{formatDateTime(systemStatus.active_signing_key.signing_started_at)}</time></dd></div>
              <div><dt class="text-small text-nya-text-tertiary">下次轮换</dt><dd class="mt-1 text-body-medium text-nya-text-primary"><time datetime={systemStatus.active_signing_key.next_rotation_at}>{formatDateTime(systemStatus.active_signing_key.next_rotation_at)}</time></dd></div>
            </dl>
          {:else}
            <p class="rounded-nya-md bg-nya-warning-soft px-4 py-3 text-body text-nya-warning" role="status">当前没有活动签名密钥。</p>
          {/if}
        </section>
      </div>
    {/if}
  {/snippet}
</ResourceState>
