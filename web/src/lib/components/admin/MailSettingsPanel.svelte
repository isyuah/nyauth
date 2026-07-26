<script lang="ts">
  import { onMount } from 'svelte';
  import {
    ApiError,
    api,
    isRecentAuthenticationError,
    type MailConfig,
    type MailErrorCategory,
    type MailSettings,
    type RegistrationMode,
  } from '$lib/api';
  import {
    buildMailCandidateInput,
    parseMailReauthenticationSnapshot,
    serializeMailReauthenticationSnapshot,
    type MailCandidateDraft,
    type MailReauthenticationAction,
    type MailReauthenticationSnapshot,
  } from '$lib/mail-settings';
  import { consumeProviderAuthError } from '$lib/stores';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import { Mail, Power, RefreshCw, RotateCcw, Send, ShieldCheck } from 'lucide-svelte';

  interface Props {
    registrationMode: RegistrationMode | null;
    onchanged?: () => void | Promise<void>;
  }

  let { registrationMode, onchanged }: Props = $props();

  const reauthenticationStorageKey = 'nyauth:reauth:mail-settings';

  let settings = $state<MailSettings | null>(null);
  let loading = $state(true);
  let loadError = $state('');
  let needsReauthentication = $state(false);
  let reauthenticationOpen = $state(false);
  let pendingReauthentication = $state<MailReauthenticationSnapshot | null>(null);
  let operation = $state<MailReauthenticationAction | ''>('');
  let operationError = $state('');
  let operationNotice = $state('');
  let testEmail = $state('');
  let password = $state('');
  let passwordless = $state(false);
  let preserveDraftOnNextLoad = $state(false);
  let disableConfirmationOpen = $state(false);
  let draft = $state<MailCandidateDraft>(defaultDraft());

  function defaultDraft(): MailCandidateDraft {
    return {
      host: '',
      port: '587',
      username: '',
      tls_mode: 'starttls',
      from_address: '',
      from_name: 'Nyauth',
      public_base_url: typeof window === 'undefined' ? '' : window.location.origin,
      connect_timeout: '10s',
      send_timeout: '30s',
    };
  }

  function draftFromConfig(config: MailConfig): MailCandidateDraft {
    return {
      host: config.host,
      port: String(config.port),
      username: config.username,
      tls_mode: config.tls_mode,
      from_address: config.from_address,
      from_name: config.from_name,
      public_base_url: config.public_base_url,
      connect_timeout: config.connect_timeout,
      send_timeout: config.send_timeout,
    };
  }

  function applyDraft(value: MailCandidateDraft) {
    draft = {
      host: value.host,
      port: value.port,
      username: value.username,
      tls_mode: value.tls_mode,
      from_address: value.from_address,
      from_name: value.from_name,
      public_base_url: value.public_base_url,
      connect_timeout: value.connect_timeout,
      send_timeout: value.send_timeout,
    };
  }

  function seedDraft(current: MailSettings) {
    const source = current.candidate || current.active;
    applyDraft(source ? draftFromConfig(source) : defaultDraft());
    password = '';
    passwordless = false;
  }

  function resetDraft() {
    if (settings) seedDraft(settings);
  }

  async function loadMailSettings(seedForm = true, allowReauthentication = true): Promise<boolean> {
    loading = true;
    loadError = '';
    try {
      const current = await api.admin.getMailSettings();
      settings = current;
      needsReauthentication = false;
      if (seedForm) seedDraft(current);
      return true;
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        settings = null;
        needsReauthentication = true;
      } else {
        loadError = errorMessage(cause, '邮件设置加载失败');
      }
      return false;
    } finally {
      loading = false;
    }
  }

  function openReauthentication(snapshot: MailReauthenticationSnapshot) {
    pendingReauthentication = snapshot;
    reauthenticationOpen = true;
  }

  function requestSettingsAccess() {
    operationError = '';
    operationNotice = '';
    openReauthentication({ action: 'load' });
  }

  function validateDraft(): string {
    const port = Number(String(draft.port ?? '').trim());
    if (!draft.host.trim()) return '请填写 SMTP 主机。';
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return 'SMTP 端口必须是 1 至 65535 之间的整数。';
    if (!draft.from_address.trim()) return '请填写发件邮箱地址。';
    if (!draft.public_base_url.trim()) return '请填写邮件链接使用的公开地址。';
    if (!draft.connect_timeout.trim() || !draft.send_timeout.trim()) return '请填写连接和发送超时。';
    if (!settings?.active && password === '' && !passwordless) {
      return '当前没有可继承的有效凭据，请输入 SMTP 密码，或明确选择无密码 SMTP。';
    }
    return '';
  }

  async function saveCandidate(event?: SubmitEvent, allowReauthentication = true, expectedRevision?: number) {
    event?.preventDefault();
    operationError = '';
    operationNotice = '';
    const validationError = validateDraft();
    if (validationError) {
      operationError = validationError;
      return;
    }
    if (!settings && expectedRevision === undefined) return;
    const revision = expectedRevision ?? settings?.state_revision ?? 0;
    const snapshot: MailReauthenticationSnapshot = {
      action: 'save',
      expected_revision: revision,
      draft: { ...draft },
      password_was_provided: password !== '',
      passwordless,
    };
    operation = 'save';
    try {
      await api.admin.saveMailCandidate(buildMailCandidateInput(revision, draft, password, passwordless));
      password = '';
      passwordless = false;
      operationNotice = '候选配置已保存。它尚未生效，请先向指定地址发送真实测试邮件。';
      await loadMailSettings(true, false);
      await onchanged?.();
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        openReauthentication(snapshot);
      } else {
        operationError = errorMessage(cause, '候选配置保存失败');
      }
    } finally {
      operation = '';
    }
  }

  async function testCandidate(allowReauthentication = true, expectedRevision?: number, versionID?: string) {
    operationError = '';
    operationNotice = '';
    const recipient = testEmail.trim();
    const candidateID = versionID || settings?.candidate?.id;
    if (!recipient) {
      operationError = '请填写接收测试邮件的地址。';
      return;
    }
    if (!settings || !candidateID) {
      operationError = '请先保存候选配置。';
      return;
    }
    const revision = expectedRevision ?? settings.state_revision;
    const snapshot: MailReauthenticationSnapshot = {
      action: 'test', expected_revision: revision, version_id: candidateID,
    };
    operation = 'test';
    try {
      const result = await api.admin.testMailCandidate(revision, candidateID, recipient);
      settings = { ...settings, state_revision: result.state_revision };
      if (result.result === 'success') {
        operationNotice = `测试邮件已成功发送（${formatDateTime(result.tested_at)}），该候选配置可在 10 分钟内激活。`;
      } else {
        operationError = `测试邮件发送失败：${errorCategoryLabel(result.error_category)}。候选配置未激活。`;
      }
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        openReauthentication(snapshot);
      } else {
        operationError = errorMessage(cause, '测试邮件发送失败');
      }
    } finally {
      operation = '';
    }
  }

  async function activateCandidate(allowReauthentication = true, expectedRevision?: number, versionID?: string) {
    operationError = '';
    operationNotice = '';
    const candidateID = versionID || settings?.candidate?.id;
    if (!settings || !candidateID) return;
    const revision = expectedRevision ?? settings.state_revision;
    const snapshot: MailReauthenticationSnapshot = {
      action: 'activate', expected_revision: revision, version_id: candidateID,
    };
    operation = 'activate';
    try {
      await api.admin.activateMailCandidate(revision, candidateID);
      operationNotice = '候选配置已激活；新领取的邮件将使用这一版本。';
      await loadMailSettings(true, false);
      await onchanged?.();
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else operationError = errorMessage(cause, '候选配置激活失败');
    } finally {
      operation = '';
    }
  }

  async function rollbackSettings(allowReauthentication = true, expectedRevision?: number) {
    operationError = '';
    operationNotice = '';
    if (!settings) return;
    const revision = expectedRevision ?? settings.state_revision;
    const snapshot: MailReauthenticationSnapshot = { action: 'rollback', expected_revision: revision };
    operation = 'rollback';
    try {
      await api.admin.rollbackMailSettings(revision);
      operationNotice = '邮件配置已回滚到上一版本。';
      await loadMailSettings(true, false);
      await onchanged?.();
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else operationError = errorMessage(cause, '邮件配置回滚失败');
    } finally {
      operation = '';
    }
  }

  async function disableMail(allowReauthentication = true, expectedRevision?: number) {
    operationError = '';
    operationNotice = '';
    if (!settings) return;
    if (registrationMode !== 'closed') {
      operationError = '禁用邮件服务前必须先把自助注册模式改为关闭。';
      return;
    }
    const revision = expectedRevision ?? settings.state_revision;
    const snapshot: MailReauthenticationSnapshot = { action: 'disable', expected_revision: revision };
    operation = 'disable';
    try {
      await api.admin.disableMail(revision);
      operationNotice = '邮件服务已禁用；待发送队列会保留，但暂停领取。';
      await loadMailSettings(true, false);
      await onchanged?.();
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) openReauthentication(snapshot);
      else operationError = errorMessage(cause, '邮件服务禁用失败');
    } finally {
      operation = '';
    }
  }

  function persistPendingReauthentication() {
    if (!pendingReauthentication) return;
    sessionStorage.setItem(
      reauthenticationStorageKey,
      serializeMailReauthenticationSnapshot(pendingReauthentication),
    );
    // The password is deliberately memory-only and must not survive a provider redirect.
    password = '';
    testEmail = '';
  }

  async function retryPendingAfterPassword() {
    const snapshot = pendingReauthentication;
    pendingReauthentication = null;
    if (!snapshot) return;
    await resumeSnapshot(snapshot);
  }

  async function resumeSnapshot(snapshot: MailReauthenticationSnapshot) {
    switch (snapshot.action) {
      case 'load':
        await loadMailSettings(!preserveDraftOnNextLoad, false);
        preserveDraftOnNextLoad = false;
        break;
      case 'save':
        await saveCandidate(undefined, false, snapshot.expected_revision);
        break;
      case 'test':
        await testCandidate(false, snapshot.expected_revision, snapshot.version_id);
        break;
      case 'activate':
        await activateCandidate(false, snapshot.expected_revision, snapshot.version_id);
        break;
      case 'rollback':
        await rollbackSettings(false, snapshot.expected_revision);
        break;
      case 'disable':
        await disableMail(false, snapshot.expected_revision);
        break;
    }
  }

  async function restoreProviderReauthentication(): Promise<boolean> {
    const raw = sessionStorage.getItem(reauthenticationStorageKey);
    if (!raw) return false;
    sessionStorage.removeItem(reauthenticationStorageKey);
    const providerError = consumeProviderAuthError();
    const snapshot = parseMailReauthenticationSnapshot(raw);
    if (!snapshot) {
      operationError = '无法恢复待处理的邮件设置，请重新检查表单。';
      await loadMailSettings(true, true);
      return true;
    }
    if (snapshot.draft) applyDraft(snapshot.draft);
    passwordless = snapshot.passwordless === true;
    password = '';
    if (providerError) {
      operationError = providerError.message;
      preserveDraftOnNextLoad = snapshot.draft !== undefined;
      needsReauthentication = true;
      loading = false;
      return true;
    }
    const loaded = await loadMailSettings(false, false);
    if (!loaded || !settings) return true;
    if (snapshot.expected_revision !== undefined && snapshot.expected_revision !== settings.state_revision) {
      operationError = '邮件设置在重新认证期间发生了变化。表单已恢复，请核对后重新保存。';
      return true;
    }
    if (snapshot.action === 'save' && snapshot.password_was_provided) {
      operationNotice = '身份验证已完成，非敏感表单已恢复。出于安全原因密码未保存，请重新输入后保存候选配置。';
      return true;
    }
    if (snapshot.action === 'test') {
      operationNotice = '身份验证已完成。测试收件地址未保存，请重新填写后发送测试邮件。';
      return true;
    }
    await resumeSnapshot(snapshot);
    return true;
  }

  function modeLabel(mode: string): string {
    return ({ fallback: '环境变量回退', active: '数据库动态配置', disabled: '已禁用' } as Record<string, string>)[mode] || mode;
  }

  function summaryStatus(current: MailSettings): string {
    if (current.mode === 'disabled') return 'disabled';
    if (!current.configured) return 'not_configured';
    return current.available ? 'ok' : 'unavailable';
  }

  function tlsModeLabel(mode: string): string {
    return ({ starttls: 'STARTTLS', implicit: '隐式 TLS', plain: '明文' } as Record<string, string>)[mode] || mode;
  }

  function errorCategoryLabel(category?: MailErrorCategory): string {
    if (!category) return '未知错误';
    return ({
      configuration: '配置错误', authentication: '认证失败', tls: 'TLS 失败',
      transport: '传输失败', recipient: '收件人被拒绝', unknown: '未知错误',
    } as Record<string, string>)[category] || category;
  }

  function errorMessage(cause: unknown, fallback: string): string {
    if (!(cause instanceof Error)) return fallback;
    if (cause instanceof ApiError && cause.retryAfter) return `${cause.message} 请在 ${cause.retryAfter} 秒后重试。`;
    return cause.message;
  }

  function formatDateTime(value?: string): string {
    if (!value) return '—';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN');
  }

  function reauthenticationDescription(): string {
    const action = pendingReauthentication?.action;
    if (action === 'load') return '查看 SMTP 配置前需要验证最近 10 分钟内的身份';
    return '修改或测试 SMTP 配置前需要验证最近 10 分钟内的身份';
  }

  onMount(async () => {
    if (!(await restoreProviderReauthentication())) await loadMailSettings();
  });
</script>

<section class="mb-4 rounded-nya-card border border-nya-border bg-nya-surface p-5 shadow-nya-card">
  <div class="mb-4 flex flex-wrap items-start justify-between gap-3">
    <div class="flex items-start gap-2">
      <Mail size={18} class="mt-0.5 text-nya-primary" />
      <div>
        <h2 class="text-card-title text-nya-text-primary">SMTP 动态配置</h2>
        <p class="mt-1 text-body text-nya-text-secondary">候选配置先保存、真实测试，再原子激活；无需重启服务。</p>
      </div>
    </div>
    {#if settings}<StatusBadge status={summaryStatus(settings)} />{/if}
  </div>

  {#if loading}
    <p class="text-small text-nya-text-tertiary" role="status">正在加载受保护的邮件设置…</p>
  {:else if needsReauthentication && !settings}
    {#if operationError}<p class="mb-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{operationError}</p>{/if}
    <div class="rounded-nya-md border border-nya-border bg-nya-surface-muted p-4">
      <p class="text-body text-nya-text-secondary">SMTP 主机、发件地址和版本历史属于受保护的运维配置，需要近期身份验证后才能查看。</p>
      <div class="mt-3"><Button variant="secondary" onclick={requestSettingsAccess}><ShieldCheck size={16} /> 验证身份并加载</Button></div>
    </div>
  {:else if loadError && !settings}
    <div class="space-y-3">
      <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{loadError}</p>
      <Button variant="secondary" onclick={() => loadMailSettings()}><RefreshCw size={16} /> 重新加载</Button>
    </div>
  {:else if settings}
    <div class="space-y-5">
      {#if loadError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{loadError}</p>{/if}
      {#if operationError}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{operationError}</p>{/if}
      {#if operationNotice}<p class="rounded-nya-sm bg-nya-success-soft px-3 py-2 text-small text-nya-success" role="status">{operationNotice}</p>{/if}

      <dl class="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div class="rounded-nya-md bg-nya-surface-muted p-4">
          <dt class="text-small text-nya-text-tertiary">运行模式</dt>
          <dd class="mt-2 text-body-medium text-nya-text-primary">{modeLabel(settings.mode)}</dd>
        </div>
        <div class="rounded-nya-md bg-nya-surface-muted p-4">
          <dt class="text-small text-nya-text-tertiary">配置状态</dt>
          <dd class="mt-2"><StatusBadge status={settings.mode === 'disabled' ? 'disabled' : settings.configured ? 'enabled' : 'not_configured'} /></dd>
        </div>
        <div class="rounded-nya-md bg-nya-surface-muted p-4">
          <dt class="text-small text-nya-text-tertiary">发送能力</dt>
          <dd class="mt-2"><StatusBadge status={settings.available ? 'ok' : 'unavailable'} /></dd>
        </div>
        <div class="rounded-nya-md bg-nya-surface-muted p-4">
          <dt class="text-small text-nya-text-tertiary">熔断器</dt>
          <dd class="mt-2 text-body-medium text-nya-text-primary">{settings.circuit.state === 'closed' ? '关闭（正常）' : '已打开'}</dd>
        </div>
      </dl>

      {#if settings.circuit.state === 'open'}
        <div class="rounded-nya-md border border-nya-danger/30 bg-nya-danger-soft p-4 text-small text-nya-danger" role="status">
          <p class="font-semibold">SMTP 发送已熔断：{errorCategoryLabel(settings.circuit.open_category)}</p>
          {#if settings.circuit.open_reason}<p class="mt-1 break-words">{settings.circuit.open_reason}</p>{/if}
          {#if settings.circuit.next_probe_at}<p class="mt-1">下次探测：{formatDateTime(settings.circuit.next_probe_at)}</p>{/if}
        </div>
      {/if}

      {#if settings.active}
        <div class="rounded-nya-md border border-nya-border p-4">
          <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h3 class="text-body-medium font-semibold text-nya-text-primary">当前有效配置</h3>
            <span class="text-small text-nya-text-tertiary">来源：{settings.active.source === 'environment' ? '环境变量' : '数据库版本'}</span>
          </div>
          <dl class="grid gap-3 text-small sm:grid-cols-2 lg:grid-cols-4">
            <div><dt class="text-nya-text-tertiary">服务器</dt><dd class="mt-1 break-all font-mono text-nya-text-primary">{settings.active.host}:{settings.active.port}</dd></div>
            <div><dt class="text-nya-text-tertiary">TLS</dt><dd class="mt-1 text-nya-text-primary">{tlsModeLabel(settings.active.tls_mode)}</dd></div>
            <div><dt class="text-nya-text-tertiary">发件地址</dt><dd class="mt-1 break-all text-nya-text-primary">{settings.active.from_address}</dd></div>
            <div><dt class="text-nya-text-tertiary">凭据</dt><dd class="mt-1 text-nya-text-primary">{settings.active.password_configured ? '已配置密码（不回显）' : '无密码'}</dd></div>
          </dl>
        </div>
      {/if}

      <form onsubmit={(event) => saveCandidate(event)} class="space-y-4 rounded-nya-md border border-nya-border p-4">
        <div>
          <h3 class="text-body-medium font-semibold text-nya-text-primary">候选配置</h3>
          <p class="mt-1 text-small text-nya-text-tertiary">保存不会立即切换发送器。密码留空时继承当前有效凭据，且服务端永不回显密码。</p>
        </div>
        <div class="grid gap-4 md:grid-cols-3">
          <Input id="mail-host" label="SMTP 主机" bind:value={draft.host} required placeholder="smtp.example.com" />
          <Input id="mail-port" label="端口" type="number" bind:value={draft.port} required placeholder="587" />
          <div>
            <label for="mail-tls-mode" class="mb-1.5 block text-body-medium text-nya-text-primary">TLS 模式</label>
            <select id="mail-tls-mode" bind:value={draft.tls_mode} class="h-[38px] w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 text-body text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24">
              <option value="starttls">STARTTLS</option>
              <option value="implicit">隐式 TLS</option>
              <option value="plain">明文（生产环境禁止）</option>
            </select>
          </div>
        </div>
        <div class="grid gap-4 md:grid-cols-2">
          <Input id="mail-username" label="SMTP 用户名（可选）" bind:value={draft.username} autocomplete="username" />
          <Input id="mail-password" label="SMTP 密码（留空继承）" type="password" bind:value={password} disabled={passwordless} autocomplete="new-password" />
        </div>
        <label class="flex cursor-pointer items-start gap-2">
          <input type="checkbox" checked={passwordless} onchange={(event) => { passwordless = event.currentTarget.checked; if (passwordless) password = ''; }} class="mt-0.5 rounded" />
          <span><span class="block text-body text-nya-text-primary">明确使用无密码 SMTP</span><span class="block text-small text-nya-text-tertiary">这会清除候选版本的 SMTP 密码；仅适用于可信内网中无需认证的服务器。</span></span>
        </label>
        <div class="grid gap-4 md:grid-cols-2">
          <Input id="mail-from-address" label="发件邮箱" type="email" bind:value={draft.from_address} required placeholder="noreply@example.com" />
          <Input id="mail-from-name" label="发件人名称" bind:value={draft.from_name} placeholder="Nyauth" />
        </div>
        <Input id="mail-public-base-url" label="邮件链接公开地址" type="url" bind:value={draft.public_base_url} required placeholder="https://auth.example.com" />
        <div class="grid gap-4 md:grid-cols-2">
          <Input id="mail-connect-timeout" label="连接超时" bind:value={draft.connect_timeout} required placeholder="10s" />
          <Input id="mail-send-timeout" label="发送超时" bind:value={draft.send_timeout} required placeholder="30s" />
        </div>
        <div class="flex flex-wrap gap-2">
          <Button type="submit" variant="primary" loading={operation === 'save'}>保存候选配置</Button>
          <Button variant="ghost" onclick={resetDraft} disabled={operation !== ''}>放弃表单修改</Button>
        </div>
      </form>

      {#if settings.candidate}
        <div class="rounded-nya-md border border-nya-primary/30 bg-nya-primary-soft/40 p-4">
          <div class="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 class="text-body-medium font-semibold text-nya-text-primary">待测试候选版本 #{settings.candidate.revision}</h3>
              <p class="mt-1 text-small text-nya-text-tertiary">创建于 {formatDateTime(settings.candidate.created_at)}；测试成功后 10 分钟内可激活。</p>
            </div>
            <span class="font-mono text-micro text-nya-text-tertiary">{settings.candidate.id}</span>
          </div>
          <div class="mt-4 grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-end">
            <Input id="mail-test-email" label="测试邮件收件地址" type="email" bind:value={testEmail} autocomplete="email" placeholder="operator@example.com" />
            <Button variant="secondary" loading={operation === 'test'} disabled={operation !== '' && operation !== 'test'} onclick={() => testCandidate()}><Send size={16} /> 发送真实测试</Button>
            <Button variant="primary" loading={operation === 'activate'} disabled={operation !== '' && operation !== 'activate'} onclick={() => activateCandidate()}><ShieldCheck size={16} /> 激活候选版本</Button>
          </div>
        </div>
      {/if}

      <div class="grid gap-4 md:grid-cols-2">
        <div class="rounded-nya-md border border-nya-border p-4">
          <h3 class="text-body-medium font-semibold text-nya-text-primary">上一有效版本</h3>
          {#if settings.previous}
            <p class="mt-2 text-small text-nya-text-secondary">版本 #{settings.previous.revision} · {settings.previous.host}:{settings.previous.port} · {tlsModeLabel(settings.previous.tls_mode)}</p>
            <div class="mt-3"><Button variant="secondary" loading={operation === 'rollback'} disabled={operation !== '' && operation !== 'rollback'} onclick={() => rollbackSettings()}><RotateCcw size={16} /> 回滚到上一版本</Button></div>
          {:else}
            <p class="mt-2 text-small text-nya-text-tertiary">当前没有可回滚版本。</p>
          {/if}
        </div>
        <div class="rounded-nya-md border border-nya-danger/30 p-4">
          <h3 class="text-body-medium font-semibold text-nya-text-primary">禁用邮件发送</h3>
          <p class="mt-2 text-small text-nya-text-secondary">禁用后停止领取 outbox，但不会删除待发送邮件。必须先关闭自助注册。</p>
          {#if registrationMode === null}<p class="mt-2 text-small text-nya-warning">注册设置仍在加载，暂不能禁用邮件。</p>{:else if registrationMode !== 'closed'}<p class="mt-2 text-small text-nya-warning">当前注册模式未关闭，暂不能禁用邮件。</p>{/if}
          <div class="mt-3"><Button variant="danger" loading={operation === 'disable'} disabled={settings.mode === 'disabled' || registrationMode !== 'closed' || operation !== ''} onclick={() => (disableConfirmationOpen = true)}><Power size={16} /> 禁用邮件服务</Button></div>
        </div>
      </div>

      <div class="flex justify-end"><Button variant="ghost" onclick={() => loadMailSettings(false)} disabled={operation !== ''}><RefreshCw size={16} /> 刷新邮件状态</Button></div>
    </div>
  {/if}
</section>

<ConfirmDialog
  bind:open={disableConfirmationOpen}
  title="禁用邮件服务"
  description="邮件 outbox 会保留但停止领取；密码恢复、邮箱验证和自助注册将无法正常发送邮件。"
  confirmLabel="确认禁用"
  confirmationText="禁用邮件"
  onconfirm={() => disableMail()}
/>

<ReauthenticationDialog
  bind:open={reauthenticationOpen}
  returnTo="/admin/system"
  description={reauthenticationDescription()}
  onauthenticated={retryPendingAfterPassword}
  onbeforeprovider={persistPendingReauthentication}
/>
