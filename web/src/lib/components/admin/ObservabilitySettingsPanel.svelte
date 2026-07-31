<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type ObservabilityPolicy,
    type ObservabilitySettings,
    type OTLPMutationResult,
    type SaveOTLPCandidateInput,
    type UpdateObservabilitySettingsInput,
  } from '$lib/api';
  import {
    buildOTLPCandidateInput,
    cloneObservabilityPolicy,
    validateObservabilityPolicy,
    validateOTLPCandidate,
  } from '$lib/observability';
  import { consumeProviderAuthError } from '$lib/stores';
  import { toast } from '$lib/toast';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import FormField from '$lib/components/ui/FormField.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { Activity, Bug, Gauge, RadioTower, RotateCcw, Save, Send, ShieldAlert } from 'lucide-svelte';

  type PendingAction =
    | { kind: 'load' }
    | { kind: 'policy'; input: UpdateObservabilitySettingsInput }
    | { kind: 'candidate'; input: SaveOTLPCandidateInput; authorization_was_provided: boolean }
    | { kind: 'test'; expected_revision: number; version_id: string }
    | { kind: 'activate'; expected_revision: number; version_id: string }
    | { kind: 'rollback' | 'disable'; expected_revision: number };

  const returnTo = '/admin/settings/observability';
  const pendingStorageKey = 'nyauth:reauth:observability-settings';
  const logLevelOptions = [
    { value: 'info', label: 'Info（推荐）' },
    { value: 'warn', label: 'Warn' },
    { value: 'error', label: 'Error' },
  ];
  const debugDurationOptions = [
    { value: '15', label: '15 分钟' },
    { value: '60', label: '1 小时' },
    { value: '360', label: '6 小时' },
    { value: '1440', label: '24 小时' },
  ];

  const emptyPolicy: ObservabilityPolicy = {
    log_level: 'info', debug_until: null,
    alerts: {
      mail_backlog_count: 100, mail_oldest_pending_age: '15m',
      audit_outbox_backlog_count: 1000, audit_oldest_pending_age: '10m',
      avatar_cleanup_pending_count: 100,
    },
  };

  let settings = $state<ObservabilitySettings | null>(null);
  let policyDraft = $state<ObservabilityPolicy>(cloneObservabilityPolicy(emptyPolicy));
  let loading = $state(true);
  let loadError = $state('');
  let policySaving = $state(false);
  let policyError = $state('');
  let policyConflict = $state(false);
  let fieldErrors = $state<Record<string, string>>({});
  let debugEnabled = $state(false);
  let debugMinutes = $state('60');

  let endpoint = $state('');
  let authorization = $state('');
  let clearAuthorization = $state(false);
  let exportInterval = $state('30s');
  let timeout = $state('5s');
  let otlpError = $state('');
  let otlpConflict = $state(false);
  let otlpFieldErrors = $state<Record<string, string>>({});
  let operation = $state('');
  let currentTime = $state(Date.now());

  let reauthOpen = $state(false);
  let pendingAction = $state<PendingAction | null>(null);
  let activateConfirmOpen = $state(false);
  let rollbackConfirmOpen = $state(false);
  let disableConfirmOpen = $state(false);

  let busy = $derived(policySaving || operation !== '');
  let candidate = $derived(settings?.otlp.candidate);
  let candidateTest = $derived(settings?.otlp.candidate_test);
  let candidateActivationEligible = $derived(Boolean(
    candidateTest?.activation_eligible
      && candidateTest.result === 'success'
      && candidateTest.valid_until
      && Date.parse(candidateTest.valid_until) >= currentTime,
  ));
  let debugActive = $derived(settings?.effective_log_level === 'debug');

  onMount(() => {
    const clock = window.setInterval(() => (currentTime = Date.now()), 30_000);
    void (async () => {
      await loadSettings(true);
      await restorePendingAction();
    })();
    return () => window.clearInterval(clock);
  });

  function formatDateTime(value?: string): string {
    if (!value) return '暂无';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  function modeLabel(mode: string): string {
    return ({ fallback: '部署配置', active: '动态配置', disabled: '已禁用' } as Record<string, string>)[mode] || mode;
  }

  function alertStatusLabel(status: string): string {
    return ({ ok: '采样正常', pending: '等待首次采样', unavailable: '采样暂不可用' } as Record<string, string>)[status] || status;
  }

  function errorCodeLabel(code?: string): string {
    if (!code) return '无';
    return ({ timeout: '连接超时', connection_or_collector_rejected: '连接失败或 Collector 拒绝', export_failed: '导出失败' } as Record<string, string>)[code] || code;
  }

  function applySettings(value: ObservabilitySettings, resetDrafts: boolean) {
    settings = value;
    if (resetDrafts) {
      policyDraft = cloneObservabilityPolicy(value.observability);
      debugEnabled = Boolean(value.observability.debug_until && Date.parse(value.observability.debug_until) > Date.now());
      const config = value.otlp.candidate ?? value.otlp.effective;
      endpoint = config?.endpoint ?? '';
      exportInterval = config?.export_interval ?? '30s';
      timeout = config?.timeout ?? '5s';
      authorization = '';
      clearAuthorization = false;
    }
    policyConflict = false;
    otlpConflict = false;
  }

  async function loadSettings(resetDrafts = true, allowReauthentication = true) {
    loading = true;
    loadError = '';
    try {
      applySettings(await api.admin.getObservabilitySettings(), resetDrafts);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        pendingAction = { kind: 'load' };
        reauthOpen = true;
        loadError = '查看可观测性配置前需要重新验证身份。';
      } else if (!settings) loadError = cause instanceof Error ? cause.message : '可观测性设置加载失败';
      else toast.error(cause instanceof Error ? cause.message : '最新可观测性设置加载失败');
    } finally {
      loading = false;
    }
  }

  function focusField(id: string) {
    requestAnimationFrame(() => document.getElementById(id)?.focus());
  }

  function buildPolicyInput(): UpdateObservabilitySettingsInput | null {
    if (!settings) return null;
    const observability = cloneObservabilityPolicy(policyDraft);
    observability.debug_until = debugEnabled
      ? new Date(Date.now() + Number(debugMinutes) * 60_000).toISOString()
      : null;
    const validation = validateObservabilityPolicy(observability);
    fieldErrors = {};
    if (validation) {
      fieldErrors = { [validation.field]: validation.message };
      policyError = validation.message;
      focusField(validation.field);
      return null;
    }
    return { expected_revision: settings.revision, observability };
  }

  async function savePolicy(event: SubmitEvent) {
    event.preventDefault();
    const input = buildPolicyInput();
    if (!input) return;
    pendingAction = { kind: 'policy', input };
    await executePolicySave(input, true);
  }

  async function executePolicySave(input: UpdateObservabilitySettingsInput, allowReauthentication: boolean) {
    policySaving = true;
    policyError = '';
    policyConflict = false;
    try {
      const updated = await api.admin.updateObservabilitySettings(input);
      pendingAction = null;
      applySettings(updated, true);
      toast.success('日志级别与运营告警阈值已更新。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        policyConflict = true;
        policyError = '设置已被其他管理员修改。当前草稿已保留，请加载最新 revision 后重新核对。';
      } else {
        toast.error(cause instanceof Error ? cause.message : '可观测性策略保存失败');
      }
    } finally {
      policySaving = false;
    }
  }

  async function refreshPolicyRevision() {
    const latest = await api.admin.getObservabilitySettings();
    settings = latest;
    policyConflict = false;
    policyError = '';
    toast.info('已加载最新 revision，未保存的策略草稿仍保留。');
  }

  function candidateInput(): SaveOTLPCandidateInput | null {
    if (!settings) return null;
    otlpFieldErrors = {};
    const values = { endpoint, authorization, export_interval: exportInterval, timeout };
    const validation = validateOTLPCandidate(values);
    if (validation) {
      otlpFieldErrors = { [validation.field]: validation.message };
      otlpError = validation.message;
      focusField(validation.field);
      return null;
    }
    if (clearAuthorization && authorization.trim()) {
      otlpError = '不能同时输入 Authorization 并选择清空凭据。';
      return null;
    }
    return buildOTLPCandidateInput(settings.otlp.state_revision, values, clearAuthorization);
  }

  async function saveCandidate(event: SubmitEvent) {
    event.preventDefault();
    const input = candidateInput();
    if (!input) return;
    pendingAction = { kind: 'candidate', input, authorization_was_provided: Boolean(input.authorization) };
    await executeCandidateSave(input, true);
  }

  async function executeCandidateSave(input: SaveOTLPCandidateInput, allowReauthentication: boolean) {
    operation = 'save';
    otlpError = '';
    otlpConflict = false;
    try {
      const result = await api.admin.saveOTLPCandidate(input);
      pendingAction = null;
      authorization = '';
      clearAuthorization = false;
      await loadSettings(false);
      if (settings) settings.otlp.state_revision = result.state_revision;
      toast.success('OTLP 候选配置已保存，请先执行真实连接测试。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) reauthOpen = true;
      else if (isAPIErrorCode(cause, 'telemetry.revision_conflict') || (cause instanceof Error && cause.message.includes('已被其他管理员修改'))) {
        otlpConflict = true;
        otlpError = 'OTLP 设置已发生变化。表单已保留，请加载最新状态后重新保存。';
      } else toast.error(cause instanceof Error ? cause.message : 'OTLP 候选配置保存失败');
    } finally {
      operation = '';
    }
  }

  async function testCandidate(allowReauthentication = true, expectedRevision?: number, versionID?: string) {
    const revision = expectedRevision ?? settings?.otlp.state_revision;
    const id = versionID ?? candidate?.id;
    if (revision === undefined || !id) return;
    pendingAction = { kind: 'test', expected_revision: revision, version_id: id };
    operation = 'test';
    otlpError = '';
    try {
      const result = await api.admin.testOTLPCandidate(revision, id);
      pendingAction = null;
      if (settings) settings.otlp.state_revision = result.state_revision;
      await loadSettings(false);
      if (result.result === 'success') toast.success('Collector 真实连接测试成功，候选配置现在可以激活。');
      else toast.error(`Collector 测试失败：${errorCodeLabel(result.error_code)}。`);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) reauthOpen = true;
      else toast.error(cause instanceof Error ? cause.message : 'OTLP 连接测试失败');
    } finally {
      operation = '';
    }
  }

  async function mutateOTLP(kind: 'activate' | 'rollback' | 'disable', allowReauthentication = true, expectedRevision?: number, versionID?: string) {
    const revision = expectedRevision ?? settings?.otlp.state_revision;
    if (revision === undefined) return;
    const id = versionID ?? candidate?.id;
    if (kind === 'activate' && !id) return;
    pendingAction = kind === 'activate'
      ? { kind, expected_revision: revision, version_id: id! }
      : { kind, expected_revision: revision };
    operation = kind;
    otlpError = '';
    try {
      let result: OTLPMutationResult;
      if (kind === 'activate') result = await api.admin.activateOTLPCandidate(revision, id!);
      else if (kind === 'rollback') result = await api.admin.rollbackOTLP(revision);
      else result = await api.admin.disableOTLP(revision);
      pendingAction = null;
      await loadSettings(true);
      toast.success(kind === 'activate' ? 'OTLP 候选配置已激活。' : kind === 'rollback' ? 'OTLP 已回滚到上一版本。' : 'OTLP 导出已禁用。');
      if (settings) settings.otlp.state_revision = result.state_revision;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) reauthOpen = true;
      else toast.error(cause instanceof Error ? cause.message : 'OTLP 状态变更失败');
    } finally {
      operation = '';
    }
  }

  async function refreshOTLPState() {
    await loadSettings(false);
    otlpConflict = false;
    otlpError = '';
    toast.info('已加载最新 OTLP 状态，候选表单仍保留。');
  }

  function persistPendingAction() {
    if (!pendingAction) return;
    if (pendingAction.kind === 'candidate') {
      const { authorization: _authorization, ...safeInput } = pendingAction.input;
      sessionStorage.setItem(pendingStorageKey, JSON.stringify({ ...pendingAction, input: safeInput }));
      return;
    }
    sessionStorage.setItem(pendingStorageKey, JSON.stringify(pendingAction));
  }

  async function resumePendingAction(action: PendingAction) {
    switch (action.kind) {
      case 'load': await loadSettings(true, false); pendingAction = null; break;
      case 'policy': await executePolicySave(action.input, false); break;
      case 'candidate': await executeCandidateSave(action.input, false); break;
      case 'test': await testCandidate(false, action.expected_revision, action.version_id); break;
      case 'activate': await mutateOTLP('activate', false, action.expected_revision, action.version_id); break;
      case 'rollback': await mutateOTLP('rollback', false, action.expected_revision); break;
      case 'disable': await mutateOTLP('disable', false, action.expected_revision); break;
    }
  }

  async function restorePendingAction() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const action = JSON.parse(raw) as PendingAction;
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      if (action.kind === 'candidate' && action.authorization_was_provided) {
        endpoint = action.input.endpoint;
        exportInterval = action.input.export_interval;
        timeout = action.input.timeout;
        toast.info('身份验证已完成。为保护凭据，请重新输入 Authorization 后保存候选配置。');
        return;
      }
      pendingAction = action;
      await resumePendingAction(action);
    } catch {
      toast.error('无法恢复待处理的可观测性操作，请重新检查设置。');
    }
  }
</script>

{#if loading && !settings}
  <p class="rounded-nya-card border border-nya-border bg-nya-surface p-5 text-small text-nya-text-tertiary" role="status">正在加载可观测性设置…</p>
{:else if !settings}
  <div class="flex items-center justify-between gap-3 rounded-nya-card border border-nya-danger/20 bg-nya-danger-soft p-4"><p class="text-small text-nya-danger" role="alert">{loadError}</p><Button variant="secondary" size="sm" onclick={() => loadSettings(true)}>重试</Button></div>
{:else}
  <div class="space-y-5">
    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
      <div class="mb-5 flex items-start gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-primary-soft text-nya-primary"><Activity size={18} /></span><div><h2 class="text-card-title text-nya-text-primary">日志与临时调试</h2><p class="mt-1 text-small text-nya-text-secondary">日志基线持续生效；Debug 仅在选定时段内临时覆盖，截止后自动恢复基线。</p></div></div>
      <form onsubmit={savePolicy} class="space-y-5">
        {#if policyError}<div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><span>{policyError}</span>{#if policyConflict}<Button variant="secondary" size="sm" onclick={refreshPolicyRevision}>加载最新 revision</Button>{/if}</div>{/if}
        <div class="grid gap-4 md:grid-cols-2">
          <FormField id="observability-log-level" label="日志基线" help="Info 记录常规运行事件；Warn 只保留警告和错误；Error 只保留错误。生产环境通常使用 Info。" error={fieldErrors['observability-log-level']}>
            <Select id="observability-log-level" bind:value={policyDraft.log_level} options={logLevelOptions} />
          </FormField>
          <div id="observability-debug" tabindex="-1" class="rounded-nya-sm border border-nya-border p-4 {fieldErrors['observability-debug'] ? 'border-nya-danger' : ''}">
            <div class="flex flex-wrap items-start justify-between gap-3"><div><p class="font-semibold text-nya-text-primary">临时 Debug</p><p class="mt-1 text-small text-nya-text-secondary">仅用于短期诊断，可能显著增加日志量。</p></div><Switch checked={debugEnabled} onchange={(checked) => (debugEnabled = checked)} label="启用临时 Debug" /></div>
            {#if debugEnabled}<div class="mt-3"><Select label="持续时间" bind:value={debugMinutes} options={debugDurationOptions} /></div>{/if}
            {#if fieldErrors['observability-debug']}<p class="mt-2 text-small text-nya-danger">{fieldErrors['observability-debug']}</p>{/if}
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-3 rounded-nya-sm bg-nya-surface-muted px-4 py-3 text-small"><span class="text-nya-text-secondary">当前有效日志级别</span><span class="font-mono font-semibold uppercase text-nya-text-primary">{settings.effective_log_level}</span>{#if debugActive && settings.observability.debug_until}<span class="text-nya-text-tertiary">自动恢复于 {formatDateTime(settings.observability.debug_until)}</span>{/if}</div>

        <fieldset class="border-t border-nya-divider pt-5">
          <legend class="flex items-center gap-2 font-semibold text-nya-text-primary"><Gauge size={17} class="text-nya-primary" /> 运营告警阈值</legend>
          <p class="mt-1 text-small text-nya-text-secondary">阈值只生成管理告警和指标，不会改变 readiness，也不会自动暂停服务。</p>
          <div class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
            <FormField id="observability-mail-backlog" label="邮件积压数量" help="待发送、失败重试和发送中的邮件总数达到此值时告警。用于发现 SMTP 故障或发送速度不足。" error={fieldErrors['observability-mail-backlog']}><input id="observability-mail-backlog" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body" type="number" min="1" max="1000000" bind:value={policyDraft.alerts.mail_backlog_count} /></FormField>
            <FormField id="observability-mail-age" label="最老待发邮件时长" help="队列中最老一封未完成邮件等待超过此时长时告警。支持 15m、2h、1h30m 等 Go 时长格式。" error={fieldErrors['observability-mail-age']}><input id="observability-mail-age" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-body" bind:value={policyDraft.alerts.mail_oldest_pending_age} spellcheck="false" /></FormField>
            <FormField id="observability-audit-backlog" label="审计投递积压数量" help="等待写入审计日志的 outbox 事件达到此值时告警。持续积压可能意味着审计分区或数据库写入异常。" error={fieldErrors['observability-audit-backlog']}><input id="observability-audit-backlog" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body" type="number" min="1" max="1000000" bind:value={policyDraft.alerts.audit_outbox_backlog_count} /></FormField>
            <FormField id="observability-audit-age" label="最老待投递审计时长" help="最老一条审计 outbox 事件等待超过此时长时告警，可比单纯数量更早发现投递停滞。" error={fieldErrors['observability-audit-age']}><input id="observability-audit-age" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-body" bind:value={policyDraft.alerts.audit_oldest_pending_age} spellcheck="false" /></FormField>
            <FormField id="observability-avatar-cleanup" label="头像清理积压数量" help="等待删除的 staging、replaced、failed 或孤立头像对象达到此值时告警。不会把正常活动头像计入。" error={fieldErrors['observability-avatar-cleanup']}><input id="observability-avatar-cleanup" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body" type="number" min="1" max="1000000" bind:value={policyDraft.alerts.avatar_cleanup_pending_count} /></FormField>
          </div>
        </fieldset>
        <Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={policySaving} disabled={operation !== ''}><Save size={16} /> 保存日志与告警设置</Button>
      </form>
    </section>

    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
      <div class="flex flex-wrap items-start justify-between gap-4"><div class="flex items-start gap-3"><span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-nya-info-soft text-nya-info"><RadioTower size={18} /></span><div><h2 class="text-card-title text-nya-text-primary">OTLP Metrics</h2><p class="mt-1 text-small text-nya-text-secondary">候选配置必须完成真实 Collector 测试后才能激活；Prometheus 指标不受这里的状态影响。</p></div></div><div class="flex items-center gap-2"><span class="text-small text-nya-text-tertiary">{modeLabel(settings.otlp.mode)}</span><StatusBadge status={settings.otlp.mode === 'disabled' ? 'disabled' : settings.otlp.runtime.configured ? (settings.otlp.runtime.available ? 'ok' : 'degraded') : 'not_configured'} /></div></div>

      {#if otlpError}<div class="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><span>{otlpError}</span>{#if otlpConflict}<Button variant="secondary" size="sm" onclick={refreshOTLPState}>加载最新状态</Button>{/if}</div>{/if}

      <dl class="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div class="rounded-nya-sm bg-nya-surface-muted p-3"><dt class="text-small text-nya-text-tertiary">运行时配置</dt><dd class="mt-1 font-semibold text-nya-text-primary">{settings.otlp.runtime.configured ? '已配置' : '未配置'}</dd></div>
        <div class="rounded-nya-sm bg-nya-surface-muted p-3"><dt class="text-small text-nya-text-tertiary">导出可用性</dt><dd class="mt-1 font-semibold text-nya-text-primary">{settings.otlp.runtime.available ? '可用' : settings.otlp.runtime.configured ? '不可用' : '未启用'}</dd></div>
        <div class="rounded-nya-sm bg-nya-surface-muted p-3"><dt class="text-small text-nya-text-tertiary">最近成功</dt><dd class="mt-1 text-small text-nya-text-primary">{formatDateTime(settings.otlp.runtime.last_success_at)}</dd></div>
        <div class="rounded-nya-sm bg-nya-surface-muted p-3"><dt class="text-small text-nya-text-tertiary">最近错误</dt><dd class="mt-1 text-small text-nya-text-primary">{formatDateTime(settings.otlp.runtime.last_error_at)}</dd>{#if settings.otlp.runtime.last_error_code}<p class="mt-1 font-mono text-micro text-nya-danger">{errorCodeLabel(settings.otlp.runtime.last_error_code)}</p>{/if}</div>
      </dl>

      <div class="mt-5 grid gap-3 lg:grid-cols-3">
        {#each [
          { label: '当前生效', value: settings.otlp.effective },
          { label: '候选版本', value: settings.otlp.candidate },
          { label: '上一版本', value: settings.otlp.previous },
        ] as summary}
          <div class="min-w-0 rounded-nya-sm border border-nya-border p-3">
            <p class="text-small font-semibold text-nya-text-primary">{summary.label}</p>
            {#if summary.value}<p class="mt-2 truncate font-mono text-small text-nya-text-secondary" title={summary.value.endpoint}>{summary.value.endpoint}</p><p class="mt-2 text-micro text-nya-text-tertiary">间隔 {summary.value.export_interval} · 超时 {summary.value.timeout} · Authorization {summary.value.authorization_configured ? '已配置' : '未配置'}</p>{:else}<p class="mt-2 text-small text-nya-text-tertiary">无</p>{/if}
          </div>
        {/each}
      </div>

      <form onsubmit={saveCandidate} class="mt-5 space-y-4 border-t border-nya-divider pt-5">
        <h3 class="font-semibold text-nya-text-primary">保存候选配置</h3>
        <div class="grid gap-4 md:grid-cols-2">
          <FormField id="observability-otlp-endpoint" label="OTLP Metrics Endpoint" help="填写 Collector 的 HTTP Metrics 接收地址，例如 https://collector.example/v1/metrics。生产环境必须使用 HTTPS。" error={otlpFieldErrors['observability-otlp-endpoint']}><input id="observability-otlp-endpoint" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small" type="url" bind:value={endpoint} autocomplete="off" spellcheck="false" placeholder="https://collector.example/v1/metrics" /></FormField>
          <FormField id="observability-otlp-authorization" label="Authorization" help="留空且不勾选清空时，服务端继承当前有效凭据；前端和 API 响应永不回显已有 Secret。"><input id="observability-otlp-authorization" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small" type="password" bind:value={authorization} autocomplete="new-password" disabled={clearAuthorization} placeholder="Bearer …" /></FormField>
          <FormField id="observability-otlp-interval" label="导出间隔" help="每次向 Collector 导出指标的目标间隔，允许 10s 至 1h。" error={otlpFieldErrors['observability-otlp-interval']}><input id="observability-otlp-interval" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-body" bind:value={exportInterval} spellcheck="false" /></FormField>
          <FormField id="observability-otlp-timeout" label="请求超时" help="单次导出的最大等待时间，允许 1s 至 30s，且不能超过导出间隔。" error={otlpFieldErrors['observability-otlp-timeout']}><input id="observability-otlp-timeout" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-body" bind:value={timeout} spellcheck="false" /></FormField>
        </div>
        <label class="flex items-start gap-2 text-small text-nya-text-secondary"><input type="checkbox" bind:checked={clearAuthorization} onchange={() => { if (clearAuthorization) authorization = ''; }} class="mt-0.5" /> <span><strong class="text-nya-text-primary">明确清空 Authorization</strong><br />新候选将不携带认证头，而不是继承当前凭据。</span></label>
        <div class="flex flex-wrap gap-2"><Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={operation === 'save'} disabled={busy && operation !== 'save'}><Save size={16} /> 保存候选</Button>{#if candidate?.id}<Button variant="secondary" requiredCapability="admin_mutations" loading={operation === 'test'} disabled={busy && operation !== 'test'} onclick={() => testCandidate()}><Send size={16} /> 真实测试</Button><Button variant="soft" requiredCapability="admin_mutations" disabled={busy || !candidateActivationEligible} onclick={() => (activateConfirmOpen = true)}><RadioTower size={16} /> 激活候选</Button>{/if}<Button variant="secondary" requiredCapability="admin_mutations" disabled={busy || !settings.otlp.previous} onclick={() => (rollbackConfirmOpen = true)}><RotateCcw size={16} /> 回滚</Button><Button variant="danger" requiredCapability="admin_mutations" disabled={busy || settings.otlp.mode === 'disabled'} onclick={() => (disableConfirmOpen = true)}><ShieldAlert size={16} /> 禁用 OTLP</Button></div>
        {#if candidateTest}<p class="text-small {candidateActivationEligible ? 'text-nya-success' : 'text-nya-danger'}" role="status">最近一次候选测试：{candidateTest.result === 'success' ? (candidateActivationEligible ? '成功，可激活' : '成功，但已过期') : `失败（${errorCodeLabel(candidateTest.error_code)}）`} · {formatDateTime(candidateTest.tested_at)}{#if candidateActivationEligible && candidateTest.valid_until} · 有效至 {formatDateTime(candidateTest.valid_until)}{/if}</p>{:else if candidate}<p class="text-small text-nya-warning" role="status">候选配置尚未完成真实连接测试。</p>{/if}
      </form>
    </section>

    <section class="rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
      <div class="flex flex-wrap items-start justify-between gap-3"><div class="flex items-center gap-2"><Bug size={18} class="text-nya-primary" /><h2 class="text-card-title text-nya-text-primary">当前运营告警</h2></div><StatusBadge status={settings.alerts.status === 'ok' ? (settings.alerts.active.length ? 'degraded' : 'ok') : settings.alerts.status} /></div>
      <p class="mt-2 text-small text-nya-text-secondary">{alertStatusLabel(settings.alerts.status)}{settings.alerts.checked_at ? ` · ${formatDateTime(settings.alerts.checked_at)}` : ''}。这些告警不影响 readiness。</p>
      {#if settings.alerts.active.length === 0}<p class="mt-4 rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success">当前没有超过阈值的运营信号。</p>{:else}<div class="mt-4 space-y-2">{#each settings.alerts.active as alert}<div class="flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-warning-soft px-3 py-2 text-small text-nya-warning"><span>{({ mail_backlog: '邮件队列积压', mail_oldest_pending: '最老待发邮件等待过久', audit_outbox_backlog: '审计投递队列积压', audit_oldest_pending: '最老审计事件等待过久', avatar_cleanup_pending: '头像对象清理积压' } as Record<string, string>)[alert.code] || alert.code}</span><span class="font-mono">{alert.current.toLocaleString()} / {alert.threshold.toLocaleString()} {alert.unit === 'seconds' ? '秒' : '项'}</span></div>{/each}</div>{/if}
    </section>
  </div>
{/if}

<ReauthenticationDialog bind:open={reauthOpen} {returnTo} description="修改可观测性运行设置前需要完成近期身份验证" onauthenticated={async () => { if (pendingAction) await resumePendingAction(pendingAction); }} onbeforeprovider={persistPendingAction} />
<ConfirmDialog bind:open={activateConfirmOpen} title="激活 OTLP 候选配置" description="激活后，后续指标导出将立即切换到已测试的候选 Collector。" confirmLabel="激活候选" onconfirm={() => mutateOTLP('activate')} />
<ConfirmDialog bind:open={rollbackConfirmOpen} title="回滚 OTLP 配置" description="这会把上一版本设为当前有效配置，并保留现有版本供后续回滚。" confirmLabel="确认回滚" confirmationText="ROLLBACK OTLP" onconfirm={() => mutateOTLP('rollback')} />
<ConfirmDialog bind:open={disableConfirmOpen} title="禁用 OTLP 导出" description="这会停止向 Collector 导出指标，但不会关闭 Prometheus /metrics，也不会影响 readiness。" confirmLabel="禁用 OTLP" confirmationText="DISABLE OTLP" onconfirm={() => mutateOTLP('disable')} />
