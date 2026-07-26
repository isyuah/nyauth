<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type SystemStatus } from '$lib/api';
  import { brandingStore } from '$lib/stores';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { Database, KeyRound, Network, Palette, Server } from 'lucide-svelte';

  let systemStatus = $state<SystemStatus | null>(null);
  let loading = $state(true);
  let error = $state('');

  let brandingTitle = $state('');
  let brandingLogoURL = $state('');
  let brandingSaving = $state(false);
  let brandingError = $state('');
  let brandingSaved = $state(false);
  let brandingSynced = false;

  $effect(() => {
    // Seed the form once from the loaded branding without clobbering edits.
    const branding = $brandingStore;
    if (!brandingSynced && branding.title) {
      brandingTitle = branding.title;
      brandingLogoURL = branding.logo_url;
      brandingSynced = true;
    }
  });

  async function saveBranding(event: SubmitEvent) {
    event.preventDefault();
    brandingSaving = true;
    brandingError = '';
    brandingSaved = false;
    try {
      const updated = await api.admin.updateBranding({ title: brandingTitle.trim(), logo_url: brandingLogoURL.trim() });
      brandingStore.set(updated);
      brandingTitle = updated.title;
      brandingLogoURL = updated.logo_url;
      brandingSaved = true;
    } catch (cause) {
      brandingError = cause instanceof Error ? cause.message : '保存失败';
    } finally {
      brandingSaving = false;
    }
  }

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

<PageHeader title="系统状态" description="查看当前版本、数据库基线与认证服务依赖的只读运行状态" />

<section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex items-center gap-2">
    <Palette size={18} class="text-nya-primary" />
    <h2 class="text-card-title text-nya-text-primary">品牌设置</h2>
  </div>
  <p class="mb-4 text-body text-nya-text-secondary">修改后无需重启，立即同步到所有实例的侧栏与登录页。Logo 留空时使用内置图标。</p>
  <form onsubmit={saveBranding} class="space-y-4">
    {#if brandingError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{brandingError}</p>{/if}
    {#if brandingSaved}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">品牌设置已保存，立即对所有实例生效。</p>{/if}
    <div class="grid gap-4 md:grid-cols-2">
      <Input id="branding-title" label="站点名称" bind:value={brandingTitle} required placeholder="Nya" />
      <Input id="branding-logo-url" label="Logo URL（可选）" bind:value={brandingLogoURL} placeholder="https://example.com/logo.png" />
    </div>
    <Button type="submit" variant="primary" loading={brandingSaving}>保存品牌设置</Button>
  </form>
</section>

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
              <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary">
                <Server size={19} />
              </span>
              <div>
                <h2 class="text-card-title text-nya-text-primary">Nyauth 服务</h2>
                <p class="mt-1 text-body text-nya-text-secondary">当前实例的总体运行状态</p>
              </div>
            </div>
            <div class="flex items-center gap-3">
              <span class="font-mono text-small text-nya-text-secondary">{systemStatus.version}</span>
              <StatusBadge status={systemStatus.status} />
            </div>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2">
            <Database size={18} class="text-nya-primary" />
            <h2 class="text-card-title text-nya-text-primary">数据库基线</h2>
          </div>
          <dl class="grid gap-4 sm:grid-cols-3">
            <div class="rounded-nya-md bg-nya-surface-muted p-4">
              <dt class="text-small text-nya-text-tertiary">Schema 状态</dt>
              <dd class="mt-2"><StatusBadge status={systemStatus.schema.status} /></dd>
            </div>
            <div class="rounded-nya-md bg-nya-surface-muted p-4">
              <dt class="text-small text-nya-text-tertiary">当前版本</dt>
              <dd class="mt-2 font-mono text-body-medium text-nya-text-primary">{systemStatus.schema.version}</dd>
            </div>
            <div class="rounded-nya-md bg-nya-surface-muted p-4">
              <dt class="text-small text-nya-text-tertiary">要求版本</dt>
              <dd class="mt-2 font-mono text-body-medium text-nya-text-primary">{systemStatus.schema.required_version}</dd>
            </div>
          </dl>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2">
            <Network size={18} class="text-nya-primary" />
            <h2 class="text-card-title text-nya-text-primary">依赖服务</h2>
          </div>
          <div class="grid gap-3 md:grid-cols-2">
            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">PostgreSQL</h3>
                <StatusBadge status={systemStatus.services.postgresql.status} />
              </div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p>
              <p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.postgresql.latency_ms)}</p>
            </article>

            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">Redis</h3>
                <StatusBadge status={systemStatus.services.redis.status} />
              </div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p>
              <p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.redis.latency_ms)}</p>
            </article>

            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">JWK</h3>
                <StatusBadge status={systemStatus.services.jwk.status} />
              </div>
              <p class="mt-3 text-small text-nya-text-tertiary">响应延迟</p>
              <p class="mt-1 font-mono text-body-medium text-nya-text-primary">{formatLatency(systemStatus.services.jwk.latency_ms)}</p>
            </article>

            <article class="rounded-nya-md border border-nya-border p-4">
              <div class="flex items-center justify-between gap-3">
                <h3 class="text-body-medium font-semibold text-nya-text-primary">Provider 快照</h3>
                <StatusBadge status={systemStatus.services.providers.status} />
              </div>
              <dl class="mt-3 grid grid-cols-2 gap-3 text-small">
                <div>
                  <dt class="text-nya-text-tertiary">响应延迟</dt>
                  <dd class="mt-1 font-mono text-nya-text-primary">{formatLatency(systemStatus.services.providers.latency_ms)}</dd>
                </div>
                <div>
                  <dt class="text-nya-text-tertiary">快照修订</dt>
                  <dd class="mt-1 font-mono text-nya-text-primary">{systemStatus.services.providers.snapshot_revision}</dd>
                </div>
              </dl>
            </article>
          </div>
        </section>

        <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
          <div class="mb-4 flex items-center gap-2">
            <KeyRound size={18} class="text-nya-primary" />
            <h2 class="text-card-title text-nya-text-primary">活动签名密钥</h2>
          </div>
          {#if systemStatus.active_signing_key}
            <dl class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <div class="min-w-0">
                <dt class="text-small text-nya-text-tertiary">Key ID</dt>
                <dd class="mt-1 truncate font-mono text-body-medium text-nya-text-primary" title={systemStatus.active_signing_key.kid}>{systemStatus.active_signing_key.kid}</dd>
              </div>
              <div>
                <dt class="text-small text-nya-text-tertiary">状态</dt>
                <dd class="mt-2"><StatusBadge status={systemStatus.active_signing_key.status} /></dd>
              </div>
              <div>
                <dt class="text-small text-nya-text-tertiary">开始签名</dt>
                <dd class="mt-1 text-body-medium text-nya-text-primary">
                  <time datetime={systemStatus.active_signing_key.signing_started_at} title={systemStatus.active_signing_key.signing_started_at}>{formatDateTime(systemStatus.active_signing_key.signing_started_at)}</time>
                </dd>
              </div>
              <div>
                <dt class="text-small text-nya-text-tertiary">下次轮换</dt>
                <dd class="mt-1 text-body-medium text-nya-text-primary">
                  <time datetime={systemStatus.active_signing_key.next_rotation_at} title={systemStatus.active_signing_key.next_rotation_at}>{formatDateTime(systemStatus.active_signing_key.next_rotation_at)}</time>
                </dd>
              </div>
            </dl>
          {:else}
            <p class="rounded-nya-md bg-nya-warning-soft px-4 py-3 text-body text-nya-warning" role="status">当前没有活动签名密钥。</p>
          {/if}
        </section>
      </div>
    {/if}
  {/snippet}
</ResourceState>
