<script lang="ts">
  import { onMount } from 'svelte';
  import {
    api, isAPIErrorCode, isRecentAuthenticationError,
    type HumanVerificationChallenge, type HumanVerificationPolicy, type HumanVerificationProof,
    type HumanVerificationSettings, type SaveHumanVerificationCandidateInput,
  } from '$lib/api';
  import { toast } from '$lib/toast';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import HumanVerificationWidget from '$lib/components/security/HumanVerificationWidget.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import ConfirmDialog from '$lib/components/ui/ConfirmDialog.svelte';
  import FormField from '$lib/components/ui/FormField.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import StatusBadge from '$lib/components/data-display/StatusBadge.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { RotateCcw, Save, Send, ShieldCheck, ShieldOff } from 'lucide-svelte';

  type PendingAction =
    | { kind: 'save'; input: SaveHumanVerificationCandidateInput }
    | { kind: 'test'; revision: number; versionID: string; proof: HumanVerificationProof }
    | { kind: 'activate'; revision: number; versionID: string; policy: HumanVerificationPolicy }
    | { kind: 'policy'; revision: number; policy: HumanVerificationPolicy }
    | { kind: 'rollback' | 'disable' | 'enable'; revision: number };

  const returnTo = '/admin/settings/human-verification';
  const pendingStorageKey = 'nyauth:reauth:human-verification';
  const defaultPolicy: HumanVerificationPolicy = {
    registration: true, login_mode: 'adaptive', login_trigger_after: 3,
    password_reset: true, email_verification_resend: true, provider_login: true,
  };

  let settings = $state<HumanVerificationSettings | null>(null);
  let policy = $state<HumanVerificationPolicy>({ ...defaultPolicy });
  let provider: 'turnstile' = $state('turnstile');
  let siteKey = $state('');
  let widgetMode: 'managed' | 'non-interactive' | 'invisible' = $state('managed');
  let secret = $state('');
  let loading = $state(true);
  let operation = $state('');
  let error = $state('');
  let conflict = $state(false);
  let testProof = $state<HumanVerificationProof | null>(null);
  let testWidgetKey = $state(0);
  let reauthOpen = $state(false);
  let pendingAction = $state<PendingAction | null>(null);
  let rollbackOpen = $state(false);
  let disableOpen = $state(false);
  let enableOpen = $state(false);
  let currentTime = $state(Date.now());

  let candidateChallenge = $derived<HumanVerificationChallenge | null>(settings?.candidate ? {
    enabled: true, required: true, available: true, provider: settings.candidate.provider,
    site_key: settings.candidate.site_key, widget_mode: settings.candidate.widget_mode, action: 'admin_test',
  } : null);
  let candidateTestValid = $derived(Boolean(
    settings?.candidate_last_test?.result === 'success'
      && Date.parse(settings.candidate_last_test.created_at) + 10 * 60_000 >= currentTime,
  ));

  onMount(() => {
    const clock = window.setInterval(() => (currentTime = Date.now()), 15_000);
    void (async () => {
      await loadSettings(true);
      await restorePendingAction();
    })();
    return () => window.clearInterval(clock);
  });

  function clonePolicy(value: HumanVerificationPolicy): HumanVerificationPolicy {
    return { ...value };
  }

  function applySettings(value: HumanVerificationSettings, resetDraft = true) {
    settings = value;
    if (resetDraft) {
      policy = clonePolicy(value.policy ?? defaultPolicy);
      const version = value.candidate ?? value.active;
      provider = version?.provider ?? 'turnstile';
      siteKey = version?.site_key ?? '';
      widgetMode = version?.widget_mode ?? 'managed';
      secret = '';
    }
    conflict = false;
    testProof = null;
    testWidgetKey += 1;
  }

  async function loadSettings(resetDraft = true) {
    loading = true;
    try {
      applySettings(await api.admin.getHumanVerificationSettings(), resetDraft);
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '人机验证设置加载失败';
    } finally {
      loading = false;
    }
  }

  function validPolicy(value: HumanVerificationPolicy): boolean {
    if (!['off', 'adaptive', 'always'].includes(value.login_mode)) return false;
    return Number.isInteger(value.login_trigger_after) && value.login_trigger_after >= 1 && value.login_trigger_after <= 100;
  }

  function candidateInput(): SaveHumanVerificationCandidateInput | null {
    if (!settings) return null;
    if (!siteKey.trim()) {
      error = '请填写 Turnstile Site Key。';
      return null;
    }
    if (!secret && !settings.candidate?.secret_configured && !settings.active?.secret_configured) {
      error = '首次配置必须填写 Turnstile Secret Key。';
      return null;
    }
    return {
      expected_revision: settings.revision, provider, site_key: siteKey.trim(), widget_mode: widgetMode,
      ...(secret ? { secret } : {}),
    };
  }

  async function saveCandidate(event: SubmitEvent) {
    event.preventDefault();
    const input = candidateInput();
    if (!input) return;
    pendingAction = { kind: 'save', input };
    await execute(pendingAction, true);
  }

  async function testCandidate() {
    if (!settings?.candidate || !testProof) {
      error = '请先完成候选配置的人机验证测试。';
      return;
    }
    pendingAction = { kind: 'test', revision: settings.revision, versionID: settings.candidate.id, proof: testProof };
    await execute(pendingAction, true);
  }

  async function activateCandidate() {
    if (!settings?.candidate || !candidateTestValid) return;
    if (!validPolicy(policy)) {
      error = '登录触发次数必须是 1 至 100 的整数。';
      return;
    }
    pendingAction = { kind: 'activate', revision: settings.revision, versionID: settings.candidate.id, policy: clonePolicy(policy) };
    await execute(pendingAction, true);
  }

  async function savePolicy(event: SubmitEvent) {
    event.preventDefault();
    if (!settings || !validPolicy(policy)) {
      error = '登录触发次数必须是 1 至 100 的整数。';
      return;
    }
    pendingAction = { kind: 'policy', revision: settings.revision, policy: clonePolicy(policy) };
    await execute(pendingAction, true);
  }

  async function execute(action: PendingAction, allowReauthentication: boolean) {
    operation = action.kind;
    error = '';
    conflict = false;
    try {
      switch (action.kind) {
        case 'save':
          await api.admin.saveHumanVerificationCandidate(action.input);
          secret = '';
          toast.success('候选配置已保存，请完成真实验证后再激活。');
          break;
        case 'test':
          await api.admin.testHumanVerificationCandidate(action.revision, action.versionID, action.proof);
          toast.success('候选配置验证成功，可在十分钟内激活。');
          break;
        case 'activate':
          await api.admin.activateHumanVerification(action.revision, action.versionID, action.policy);
          toast.success('人机验证配置与策略已激活。');
          break;
        case 'policy':
          await api.admin.updateHumanVerificationPolicy(action.revision, action.policy);
          toast.success('人机验证策略已更新。');
          break;
        case 'rollback':
          await api.admin.rollbackHumanVerification(action.revision);
          toast.success('已回滚到上一版本。');
          break;
        case 'disable':
          await api.admin.disableHumanVerification(action.revision);
          toast.success('人机验证已禁用。');
          break;
        case 'enable':
          await api.admin.enableHumanVerification(action.revision);
          toast.success('人机验证已重新启用。');
          break;
      }
      pendingAction = null;
      await loadSettings(true);
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'human_verification.revision_conflict')) {
        conflict = true;
        error = '设置已被其他管理员修改。草稿已保留，请加载最新 revision 后重新核对。';
      } else {
        error = cause instanceof Error ? cause.message : '人机验证设置操作失败';
        if (action.kind === 'test') await loadSettings(false);
      }
      if (action.kind === 'test') { testProof = null; testWidgetKey += 1; }
    } finally {
      operation = '';
    }
  }

  function openRollback() {
    if (settings) rollbackOpen = true;
  }

  function openDisable() {
    if (settings) disableOpen = true;
  }

  function openEnable() {
    if (settings?.active) enableOpen = true;
  }

  async function confirmStateMutation(kind: 'rollback' | 'disable' | 'enable') {
    if (!settings) return;
    pendingAction = { kind, revision: settings.revision };
    await execute(pendingAction, true);
  }

  function persistPendingAction() {
    if (!pendingAction) return;
    if (pendingAction.kind === 'save' || pendingAction.kind === 'test') {
      sessionStorage.setItem(pendingStorageKey, JSON.stringify({ kind: `${pendingAction.kind}_manual` }));
      return;
    }
    sessionStorage.setItem(pendingStorageKey, JSON.stringify(pendingAction));
  }

  async function restorePendingAction() {
    const raw = sessionStorage.getItem(pendingStorageKey);
    if (!raw) return;
    sessionStorage.removeItem(pendingStorageKey);
    try {
      const restored = JSON.parse(raw) as PendingAction | { kind: 'save_manual' | 'test_manual' };
      if (restored.kind === 'save_manual') {
        error = '身份验证已完成。Secret Key 未写入浏览器存储，请重新填写后保存。';
        return;
      }
      if (restored.kind === 'test_manual') {
        error = '身份验证已完成。请重新完成人机验证并发送测试。';
        return;
      }
      if (!['save', 'test', 'activate', 'policy', 'rollback', 'disable', 'enable'].includes(restored.kind)) {
        throw new Error('unsupported restored action');
      }
      const action = restored as PendingAction;
      pendingAction = action;
      await execute(action, false);
    } catch {
      error = '无法恢复身份验证前的操作，请重新提交。';
    }
  }
</script>

{#if loading && !settings}
  <p class="py-8 text-center text-body text-nya-text-tertiary">正在加载人机验证设置…</p>
{:else if !settings}
  <p class="rounded-nya-sm bg-nya-danger-soft px-4 py-3 text-body text-nya-danger" role="alert">{error || '人机验证设置不可用'}</p>
{:else}
  <div class="space-y-6">
    {#if error}<div class="rounded-nya-sm border border-nya-danger/20 bg-nya-danger-soft px-4 py-3 text-small text-nya-danger" role="alert">{error}</div>{/if}
    {#if conflict}<Button variant="secondary" size="sm" onclick={() => loadSettings(false)}>加载最新 revision</Button>{/if}

    <section class="border-b border-nya-divider pb-6">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div><h2 class="text-title-sm font-semibold text-nya-text-primary">运行状态</h2><p class="mt-1 text-small text-nya-text-secondary">主动禁用或上游故障都不会改变 readiness。</p></div>
        <div class="flex items-center gap-2"><StatusBadge status={settings.mode === 'active' && settings.runtime.available ? 'active' : settings.mode === 'disabled' ? 'inactive' : 'warning'} /><span class="text-small text-nya-text-secondary">{settings.mode === 'active' && settings.runtime.available ? '运行中' : settings.mode === 'disabled' ? '已禁用' : '不可用'}</span></div>
      </div>
      <dl class="mt-4 grid gap-3 sm:grid-cols-3 text-small"><div><dt class="text-nya-text-tertiary">当前 Provider</dt><dd class="mt-1 text-nya-text-primary">{settings.active?.provider === 'turnstile' ? 'Cloudflare Turnstile' : '无'}</dd></div><div><dt class="text-nya-text-tertiary">配置 revision</dt><dd class="mt-1 text-nya-text-primary">{settings.revision}</dd></div><div><dt class="text-nya-text-tertiary">最后更新</dt><dd class="mt-1 text-nya-text-primary">{new Date(settings.updated_at).toLocaleString('zh-CN')}</dd></div></dl>
    </section>

    <section class="border-b border-nya-divider pb-6">
      <h2 class="text-title-sm font-semibold text-nya-text-primary">验证器候选配置</h2>
      <p class="mt-1 text-small text-nya-text-secondary">Secret Key 只会加密保存且不会回显；留空会继承候选或当前有效版本。</p>
      <form class="mt-4 grid gap-4 md:grid-cols-2" onsubmit={saveCandidate}>
        <Select label="验证器" bind:value={provider} options={[{ value: 'turnstile', label: 'Cloudflare Turnstile' }]} />
        <div>
          <Select label="Cloudflare Widget 模式" bind:value={widgetMode} options={[{ value: 'managed', label: 'Managed（推荐）' }, { value: 'non-interactive', label: 'Non-interactive' }, { value: 'invisible', label: 'Invisible' }]} />
          <p class="mt-1.5 text-small text-nya-text-tertiary">必须与 Cloudflare 控制台中该 Site Key 的模式一致；Nyauth 只按此设置控制页面呈现。</p>
        </div>
        <Input id="human-site-key" label="Site Key" bind:value={siteKey} required autocomplete="off" />
        <Input id="human-secret-key" label="Secret Key" type="password" bind:value={secret} autocomplete="new-password" placeholder={settings.candidate?.secret_configured || settings.active?.secret_configured ? '留空以继承现有密钥' : '首次配置必须填写'} />
        <div class="md:col-span-2"><Button type="submit" variant="primary" loading={operation === 'save'}><Save size={16} />保存候选</Button></div>
      </form>

      {#if candidateChallenge}
        <div class="mt-5 max-w-md rounded-nya-sm border border-nya-border bg-nya-surface-muted p-4">
          <p class="text-body-medium font-semibold text-nya-text-primary">候选配置真实测试</p>
          <p class="mt-1 text-small text-nya-text-secondary">使用候选 Site Key 渲染 Widget，并由服务器使用候选 Secret Key 调用 Siteverify。</p>
          <div class="mt-3">{#key testWidgetKey}<HumanVerificationWidget challenge={candidateChallenge} bind:proof={testProof} onerror={(message) => (error = message)} />{/key}</div>
          <Button variant="secondary" loading={operation === 'test'} disabled={!testProof} onclick={testCandidate}><Send size={16} />发送验证测试</Button>
          {#if settings.candidate_last_test}<p class="mt-2 text-small {candidateTestValid ? 'text-nya-success' : 'text-nya-text-tertiary'}">最近测试：{settings.candidate_last_test.result === 'success' ? '成功' : `失败（${settings.candidate_last_test.error_code || 'unknown'}）`} · {new Date(settings.candidate_last_test.created_at).toLocaleString('zh-CN')}</p>{/if}
        </div>
      {/if}
    </section>

    <section class="border-b border-nya-divider pb-6">
      <h2 class="text-title-sm font-semibold text-nya-text-primary">保护策略</h2>
      <p class="mt-1 text-small text-nya-text-secondary">Provider 登录启用后，所有外部登录在跳转前都会验证，因为此时还无法判断上游身份是否已有本地账户。</p>
      <form class="mt-4 space-y-4" onsubmit={savePolicy}>
        <div class="grid gap-3 sm:grid-cols-2">
          <Switch bind:checked={policy.registration} label="自助注册" help="保护公开注册提交，防止机器人批量创建账户；只有注册模式开放时才会生效。" />
          <Switch bind:checked={policy.password_reset} label="密码重置请求" help="保护公开的密码重置邮件请求；仍保持不可枚举响应，不影响已登录用户修改密码。" />
          <Switch bind:checked={policy.email_verification_resend} label="验证邮件重发" help="保护公开的验证邮件重发入口；仍保持不可枚举响应，防止被用来批量触发邮件。" />
          <Switch bind:checked={policy.provider_login} label="Provider 登录与首次开户" help="在跳转 GitHub、Google 等外部身份 Provider 前验证；因为跳转前还不知道用户是否已有本地账户。" />
        </div>
        <div class="grid gap-4 md:grid-cols-2"><Select label="密码登录" bind:value={policy.login_mode} options={[{ value: 'off', label: '不要求' }, { value: 'adaptive', label: '失败次数触发（推荐）' }, { value: 'always', label: '每次都要求' }]} /><FormField id="human-login-trigger" label="触发次数" help="Adaptive 模式下，同一用户名或 IP 在当前限流窗口达到该次数后要求验证。"><input id="human-login-trigger" class="h-[38px] w-full rounded-nya-sm border border-nya-border-strong bg-nya-surface px-3 text-body focus:outline-none focus:ring-2 focus:ring-nya-primary/24" type="number" min="1" max="100" step="1" bind:value={policy.login_trigger_after} disabled={policy.login_mode !== 'adaptive'} /></FormField></div>
        <div class="flex flex-wrap gap-2"><Button type="submit" variant="secondary" loading={operation === 'policy'} disabled={settings.mode !== 'active'}><Save size={16} />保存策略</Button>{#if settings.candidate}<Button type="button" variant="primary" loading={operation === 'activate'} disabled={!candidateTestValid} onclick={activateCandidate}><ShieldCheck size={16} />激活候选与策略</Button>{/if}</div>
      </form>
    </section>

    <section>
      <h2 class="text-title-sm font-semibold text-nya-text-primary">恢复操作</h2>
      <div class="mt-3 flex flex-wrap gap-2">
        <Button variant="secondary" disabled={!settings.previous || settings.mode === 'disabled'} onclick={openRollback}><RotateCcw size={16} />回滚上一版本</Button>
        {#if settings.mode === 'disabled'}
          <Button variant="primary" disabled={!settings.active} onclick={openEnable}><ShieldCheck size={16} />重新启用</Button>
        {:else}
          <Button variant="danger" onclick={openDisable}><ShieldOff size={16} />禁用人机验证</Button>
        {/if}
      </div>
    </section>
  </div>
{/if}

<ReauthenticationDialog bind:open={reauthOpen} {returnTo} description="修改人机验证设置前需要完成近期身份验证" onauthenticated={async () => { if (pendingAction) await execute(pendingAction, false); }} onbeforeprovider={persistPendingAction} />
<ConfirmDialog bind:open={rollbackOpen} title="回滚人机验证配置" description="上一版本将立即成为有效配置，当前保护策略保持不变。" confirmLabel="确认回滚" confirmationText="ROLLBACK HUMAN VERIFICATION" onconfirm={() => confirmStateMutation('rollback')} />
<ConfirmDialog bind:open={disableOpen} title="禁用人机验证" description="公开入口将不再要求第三方挑战；当前验证器配置和策略会保留，可随时重新启用。Redis 限流仍会继续生效。" confirmLabel="确认禁用" confirmationText="DISABLE HUMAN VERIFICATION" onconfirm={() => confirmStateMutation('disable')} />
<ConfirmDialog bind:open={enableOpen} title="重新启用人机验证" description="将使用当前保留的验证器配置和策略恢复公开入口保护。" confirmLabel="确认启用" onconfirm={() => confirmStateMutation('enable')} />
