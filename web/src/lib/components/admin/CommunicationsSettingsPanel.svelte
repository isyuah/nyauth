<script lang="ts">
  import { onMount, tick } from 'svelte';
  import {
    api,
    isAPIErrorCode,
    isRecentAuthenticationError,
    type AnnouncementSettings,
    type CommunicationsSettings,
    type EmailTemplateContent,
    type EmailTemplatePreview,
    type EmailTemplateSettings,
    type UpdateCommunicationsSettingsInput,
  } from '$lib/api';
  import { consumeProviderAuthError, sessionStore } from '$lib/stores';
  import { isSafeAnnouncementLink } from '$lib/announcement';
  import { toast } from '$lib/toast';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import EmailVariableButtons from '$lib/components/admin/EmailVariableButtons.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import { Eye, Mail, Megaphone, RefreshCw, Send } from 'lucide-svelte';

  let { returnTo = '/admin/settings/communications' }: { returnTo?: string } = $props();

  type Section = 'announcement' | 'email';
  type PendingAction =
    | { kind: 'save'; input: UpdateCommunicationsSettingsInput }
    | { kind: 'test'; templateID: string; recipient: string; email: EmailTemplateSettings };
  type StoredProviderDraft = {
    kind: 'save' | 'test';
    input: UpdateCommunicationsSettingsInput;
    template_id?: string;
  };

  const providerDraftKey = 'nyauth:reauth:communications-settings';
  const templateLabels: Record<string, string> = {
    'account.password_reset': '重置密码',
    'account.password_changed': '密码已修改',
    'account.email_verification': '验证邮箱',
    'account.email_change_confirm': '确认邮箱变更',
    'account.email_changed_old': '原邮箱变更通知',
    'account.email_changed_new': '新邮箱确认通知',
    'security.role_changed': '角色变更',
    'security.status_changed': '账户状态变更',
    'security.password_configured': '本地密码已设置',
    'security.password_reset_admin': '管理员重置密码',
    'security.identity_bound': '外部身份已绑定',
    'security.identity_unbound': '外部身份已解绑',
  };

  let section = $state<Section>('announcement');
  let settings = $state<CommunicationsSettings | null>(null);
  let email = $state<EmailTemplateSettings>({ footer: '', templates: {} });
  let announcement = $state<AnnouncementSettings>(emptyAnnouncement());
  let startsAt = $state('');
  let endsAt = $state('');
  let selectedTemplateID = $state('');
  let preview = $state<EmailTemplatePreview | null>(null);
  let previewedTemplateID = $state('');
  let previewMode = $state<'html' | 'text'>('html');
  let loading = $state(true);
  let loadError = $state('');
  let saving = $state(false);
  let previewing = $state(false);
  let testing = $state(false);
  let formError = $state('');
  let conflict = $state(false);
  let reauthOpen = $state(false);
  let pendingAction = $state<PendingAction | null>(null);

  let templateOptions = $derived(Object.keys(email.templates).map((id) => ({ value: id, label: templateLabels[id] ?? id })));
  let selectedTemplate = $derived(email.templates[selectedTemplateID] ?? null);
  let testRecipient = $derived($sessionStore.session?.email_verified ? ($sessionStore.session.user.email?.trim() ?? '') : '');
  let testEmailAvailable = $derived(testRecipient !== '');
  let variableRules = $derived(settings?.template_variables[selectedTemplateID] ?? {
    subject: [], heading: [], body: [], button_label: [], required_body: [],
  });

  function emptyAnnouncement(): AnnouncementSettings {
    return {
      version: 0,
      enabled: false,
      severity: 'info',
      title: '',
      message: '',
      link_label: '',
      link_url: '',
      dismissible: true,
      starts_at: null,
      ends_at: null,
    };
  }

  function cloneEmail(value: EmailTemplateSettings): EmailTemplateSettings {
    return {
      footer: value.footer,
      templates: Object.fromEntries(Object.entries(value.templates).map(([id, content]) => [id, { ...content }])),
    };
  }

  function applySettings(value: CommunicationsSettings) {
    settings = value;
    email = cloneEmail(value.email);
    announcement = { ...value.announcement };
    startsAt = toLocalDateTime(value.announcement.starts_at);
    endsAt = toLocalDateTime(value.announcement.ends_at);
    const templateIDs = Object.keys(value.email.templates);
    if (!templateIDs.includes(selectedTemplateID)) selectedTemplateID = templateIDs[0] ?? '';
    preview = null;
    previewedTemplateID = '';
    conflict = false;
    formError = '';
  }

  async function loadSettings() {
    loading = true;
    loadError = '';
    try {
      applySettings(await api.admin.getCommunicationsSettings());
    } catch (cause) {
      loadError = message(cause, '沟通设置加载失败');
    } finally {
      loading = false;
    }
  }

  function updateTemplate(field: keyof EmailTemplateContent, value: string) {
    const current = email.templates[selectedTemplateID];
    if (!current) return;
    email.templates[selectedTemplateID] = { ...current, [field]: value };
  }

  async function insertVariable(field: keyof EmailTemplateContent, variable: string) {
    const current = email.templates[selectedTemplateID];
    if (!current) return;
    const elementIDs: Record<keyof EmailTemplateContent, string> = {
      subject: 'communications-email-subject',
      heading: 'communications-email-heading',
      body: 'communications-email-body',
      button_label: 'communications-email-button',
    };
    const element = document.getElementById(elementIDs[field]) as HTMLInputElement | HTMLTextAreaElement | null;
    const value = current[field] ?? '';
    const start = element?.selectionStart ?? value.length;
    const end = element?.selectionEnd ?? start;
    const token = `{{${variable}}}`;
    updateTemplate(field, `${value.slice(0, start)}${token}${value.slice(end)}`);
    await tick();
    const updated = document.getElementById(elementIDs[field]) as HTMLInputElement | HTMLTextAreaElement | null;
    updated?.focus();
    updated?.setSelectionRange(start + token.length, start + token.length);
  }

  function buildInput(): UpdateCommunicationsSettingsInput | null {
    if (!settings) return null;
    return {
      expected_revision: settings.revision,
      email: cloneEmail(email),
      announcement: {
        ...announcement,
        starts_at: toISOStringOrNull(startsAt),
        ends_at: toISOStringOrNull(endsAt),
      },
    };
  }

  function validateInput(input: UpdateCommunicationsSettingsInput): string {
    for (const [id, content] of Object.entries(input.email.templates)) {
      const label = templateLabels[id] ?? id;
      if (!content.subject.trim()) return `${label}的邮件主题不能为空。`;
      if (!content.heading.trim()) return `${label}的标题不能为空。`;
      if (!content.body.trim()) return `${label}的正文不能为空。`;
      if ('button_label' in content && !content.button_label?.trim()) return `${label}的按钮文字不能为空。`;
      const rules = settings?.template_variables[id];
      if (!rules) return `${label}缺少变量规则，请加载最新设置后重试。`;
      const subjectError = templateVariableError(content.subject, rules.subject, `${label}的邮件主题`);
      if (subjectError) return subjectError;
      const headingError = templateVariableError(content.heading, rules.heading, `${label}的内容标题`);
      if (headingError) return headingError;
      const bodyError = templateVariableError(content.body, rules.body, `${label}的正文`);
      if (bodyError) return bodyError;
      const buttonError = templateVariableError(content.button_label ?? '', rules.button_label, `${label}的按钮文字`);
      if (buttonError) return buttonError;
      const bodyVariables = extractTemplateVariables(content.body);
      if (bodyVariables === null) return `${label}的正文包含格式错误的模板变量。`;
      const missing = rules.required_body.filter((variable) => !bodyVariables.includes(variable));
      if (missing.length > 0) return `${label}的正文必须保留变量 ${missing.map((variable) => `{{${variable}}}`).join('、')}。`;
    }
    const footerError = templateVariableError(input.email.footer, ['site_name'], '统一页脚');
    if (footerError) return footerError;
    const value = input.announcement;
    if (value.enabled && (!value.title.trim() || !value.message.trim())) return '启用公告时必须填写标题和正文。';
    if ((value.link_label.trim() === '') !== (value.link_url.trim() === '')) return '公告链接文字和链接地址必须同时填写。';
    if (value.link_url && !validAnnouncementURL(value.link_url)) return '公告链接必须是站内路径或 HTTPS 地址。';
    if (value.starts_at && value.ends_at && Date.parse(value.ends_at) <= Date.parse(value.starts_at)) return '公告结束时间必须晚于开始时间。';
    return '';
  }

  function extractTemplateVariables(value: string): string[] | null {
    const variables: string[] = [];
    const remainder = value.replace(/\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}/gi, (_match, variable: string) => {
      variables.push(variable);
      return '';
    });
    return remainder.includes('{{') || remainder.includes('}}') ? null : variables;
  }

  function templateVariableError(value: string, allowed: string[], field: string): string {
    const variables = extractTemplateVariables(value);
    if (variables === null) return `${field}包含格式错误的模板变量。`;
    const unsupported = variables.find((variable) => !allowed.includes(variable));
    return unsupported ? `${field}不允许使用变量 {{${unsupported}}}。` : '';
  }

  async function submitSave(event: SubmitEvent) {
    event.preventDefault();
    const input = buildInput();
    if (!input) return;
    const validation = validateInput(input);
    formError = validation;
    conflict = false;
    if (validation) {
      toast.error(validation);
      return;
    }
    pendingAction = { kind: 'save', input };
    await executeSave(input, true);
  }

  async function executeSave(input: UpdateCommunicationsSettingsInput, allowReauthentication: boolean) {
    saving = true;
    formError = '';
    conflict = false;
    try {
      const updated = await api.admin.updateCommunicationsSettings(input);
      pendingAction = null;
      applySettings(updated);
      toast.success('沟通设置已保存，公告和后续事务邮件将使用新配置。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else if (isAPIErrorCode(cause, 'settings.revision_conflict')) {
        conflict = true;
        formError = '设置已被其他管理员修改。当前草稿已保留，请加载最新设置后重新核对。';
      } else {
        toast.error(message(cause, '沟通设置保存失败'));
      }
    } finally {
      saving = false;
    }
  }

  async function requestPreview() {
    if (!selectedTemplateID) return;
    previewing = true;
    try {
      preview = await api.admin.previewEmailTemplate(selectedTemplateID, cloneEmail(email));
      previewedTemplateID = selectedTemplateID;
    } catch (cause) {
      toast.error(message(cause, '邮件预览生成失败'));
    } finally {
      previewing = false;
    }
  }

  async function requestTest() {
    if (!testEmailAvailable) {
      toast.error('请先验证当前管理员的邮箱地址，再发送测试邮件。');
      return;
    }
    const action: PendingAction = { kind: 'test', templateID: selectedTemplateID, recipient: testRecipient, email: cloneEmail(email) };
    pendingAction = action;
    await executeTest(action, true);
  }

  async function executeTest(action: Extract<PendingAction, { kind: 'test' }>, allowReauthentication: boolean) {
    testing = true;
    try {
      await api.admin.testEmailTemplate(action.templateID, action.recipient, action.email);
      pendingAction = null;
      toast.success('测试邮件已发送。');
    } catch (cause) {
      if (allowReauthentication && isRecentAuthenticationError(cause)) {
        reauthOpen = true;
      } else {
        toast.error(message(cause, '测试邮件发送失败'));
      }
    } finally {
      testing = false;
    }
  }

  async function retryPendingAction() {
    const action = pendingAction;
    if (!action) return;
    if (action.kind === 'save') await executeSave(action.input, false);
    else await executeTest(action, false);
  }

  function persistProviderDraft() {
    const input = pendingAction?.kind === 'save' ? pendingAction.input : buildInput();
    if (!input || !pendingAction) return;
    const stored: StoredProviderDraft = {
      kind: pendingAction.kind,
      input,
      template_id: pendingAction.kind === 'test' ? pendingAction.templateID : undefined,
    };
    sessionStorage.setItem(providerDraftKey, JSON.stringify(stored));
  }

  async function restoreProviderDraft() {
    const raw = sessionStorage.getItem(providerDraftKey);
    if (!raw) return;
    sessionStorage.removeItem(providerDraftKey);
    try {
      const stored = JSON.parse(raw) as StoredProviderDraft;
      if ((stored.kind !== 'save' && stored.kind !== 'test') || !Number.isSafeInteger(stored.input?.expected_revision)) throw new TypeError('invalid communications draft');
      const current = settings;
      if (!current) throw new TypeError('communications settings unavailable');
      applySettings({
        revision: stored.input.expected_revision,
        email: stored.input.email,
        announcement: stored.input.announcement,
        template_variables: current.template_variables,
      });
      const providerError = consumeProviderAuthError();
      if (providerError) {
        toast.error(providerError.message);
        return;
      }
      if (stored.kind === 'save') {
        pendingAction = { kind: 'save', input: stored.input };
        await executeSave(stored.input, false);
      } else {
        section = 'email';
        const templateID = stored.template_id ?? '';
        if (!templateID || !email.templates[templateID]) throw new TypeError('invalid stored email template');
        selectedTemplateID = templateID;
        if (!testEmailAvailable) {
          toast.warning('身份验证已完成，但当前管理员没有已验证邮箱，无法发送测试邮件。');
          return;
        }
        const action: PendingAction = { kind: 'test', templateID, recipient: testRecipient, email: cloneEmail(email) };
        pendingAction = action;
        await executeTest(action, false);
      }
    } catch {
      toast.error('无法恢复待处理的沟通设置草稿，请重新检查表单。');
    }
  }

  function toLocalDateTime(value: string | null): string {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
    return local.toISOString().slice(0, 16);
  }

  function toISOStringOrNull(value: string): string | null {
    if (!value.trim()) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }

  function validAnnouncementURL(value: string): boolean {
    return isSafeAnnouncementLink(value);
  }

  function message(cause: unknown, fallback: string): string {
    return cause instanceof Error ? cause.message : fallback;
  }

  onMount(async () => {
    await loadSettings();
    await restoreProviderDraft();
  });
</script>

<section class="rounded-nya-card border border-nya-border bg-nya-surface shadow-nya-card">
  <div class="flex flex-col gap-3 border-b border-nya-divider px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
    <div>
      <h2 class="text-card-title text-nya-text-primary">站点沟通</h2>
      <p class="mt-1 text-small text-nya-text-secondary">统一管理全站公告和事务邮件文案，不改变 SMTP 连接配置。</p>
    </div>
    <div class="inline-flex self-start rounded-nya-sm bg-nya-surface-muted p-1" role="tablist" aria-label="沟通设置分区">
      <button type="button" role="tab" aria-selected={section === 'announcement'} onclick={() => (section = 'announcement')} class="flex h-8 items-center gap-2 rounded-nya-xs px-3 text-small font-semibold {section === 'announcement' ? 'bg-nya-surface text-nya-primary shadow-nya-xs' : 'text-nya-text-secondary'}"><Megaphone size={14} /> 站点公告</button>
      <button type="button" role="tab" aria-selected={section === 'email'} onclick={() => (section = 'email')} class="flex h-8 items-center gap-2 rounded-nya-xs px-3 text-small font-semibold {section === 'email' ? 'bg-nya-surface text-nya-primary shadow-nya-xs' : 'text-nya-text-secondary'}"><Mail size={14} /> 邮件模板</button>
    </div>
  </div>

  {#if loading}
    <p class="px-5 py-8 text-small text-nya-text-tertiary" role="status">正在加载沟通设置…</p>
  {:else if !settings}
    <div class="flex items-center justify-between gap-3 px-5 py-6"><p class="text-small text-nya-danger" role="alert">{loadError}</p><Button variant="secondary" size="sm" onclick={loadSettings}>重试</Button></div>
  {:else}
    <form onsubmit={submitSave}>
      {#if formError}
        <div class="mx-5 mt-4 flex flex-wrap items-center justify-between gap-3 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert"><span>{formError}</span>{#if conflict}<Button variant="secondary" size="sm" onclick={loadSettings}><RefreshCw size={14} /> 加载最新设置</Button>{/if}</div>
      {/if}

      {#if section === 'announcement'}
        <div class="grid gap-0 lg:grid-cols-[minmax(0,1fr)_minmax(320px,0.8fr)]">
          <div class="space-y-4 px-5 py-5 lg:border-r lg:border-nya-divider">
            <div class="flex items-start justify-between gap-4"><div><p class="font-semibold text-nya-text-primary">显示站点公告</p><p class="mt-1 text-small text-nya-text-secondary">发布后通过实时事件同步到已打开的页面。</p></div><Switch checked={announcement.enabled} onchange={(checked) => (announcement.enabled = checked)} label="显示站点公告" /></div>
            <Select id="communications-announcement-severity" label="严重程度" bind:value={announcement.severity} options={[{ value: 'info', label: '信息' }, { value: 'warning', label: '警告' }, { value: 'critical', label: '严重' }]} />
            <Input id="communications-announcement-title" label="公告标题" bind:value={announcement.title} maxlength={120} placeholder="例如：计划维护通知" />
            <div><label for="communications-announcement-message" class="mb-1.5 block text-body-medium text-nya-text-primary">公告正文</label><textarea id="communications-announcement-message" bind:value={announcement.message} maxlength="1000" rows="4" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24" placeholder="说明影响范围和预计恢复时间。"></textarea></div>
            <div class="grid gap-4 sm:grid-cols-2"><Input id="communications-link-label" label="链接文字" bind:value={announcement.link_label} maxlength={64} placeholder="查看详情" /><Input id="communications-link-url" label="链接地址" bind:value={announcement.link_url} inputmode="url" placeholder="/status 或 https://…" /></div>
            <div class="grid gap-4 sm:grid-cols-2"><Input id="communications-starts-at" label="开始时间（可选）" type="datetime-local" bind:value={startsAt} /><Input id="communications-ends-at" label="结束时间（可选）" type="datetime-local" bind:value={endsAt} /></div>
            <label class="flex cursor-pointer items-start gap-2"><input type="checkbox" bind:checked={announcement.dismissible} class="mt-0.5 rounded" /><span><span class="block text-body text-nya-text-primary">允许关闭</span><span class="block text-small text-nya-text-tertiary">关闭状态按公告版本保存在浏览器；修改公告后会再次显示。</span></span></label>
          </div>
          <div class="bg-nya-surface-muted px-5 py-5">
            <p class="mb-3 text-small font-semibold text-nya-text-secondary">横幅预览</p>
            <div class="border-l-4 px-4 py-3 {announcement.severity === 'critical' ? 'border-nya-danger bg-nya-danger-soft text-nya-danger' : announcement.severity === 'warning' ? 'border-nya-warning bg-nya-warning-soft text-nya-warning' : 'border-nya-info bg-nya-info-soft text-nya-info'}">
              <p class="font-semibold">{announcement.title || '公告标题'}</p><p class="mt-1 text-small">{announcement.message || '公告正文会以纯文本显示。'}</p>{#if announcement.link_label}<span class="mt-2 inline-block text-small font-semibold underline">{announcement.link_label}</span>{/if}
            </div>
            <p class="mt-3 text-micro text-nya-text-tertiary">公告不会解析 HTML；开启“允许关闭”后会显示关闭按钮。</p>
          </div>
        </div>
      {:else}
        <div class="border-b border-nya-divider px-5 py-4">
          <div class="grid gap-4 md:grid-cols-[minmax(240px,0.6fr)_minmax(0,1fr)] md:items-end">
            <Select id="communications-template" label="邮件类型" bind:value={selectedTemplateID} options={templateOptions} />
            <div><p class="mb-1.5 text-body-medium text-nya-text-primary">变量规则</p><p class="min-h-[38px] text-small text-nya-text-secondary">变量按字段隔离；标记“必需”的变量必须保留在正文中，不能移动到主题或标题。</p></div>
          </div>
        </div>
        <div class="grid gap-0 lg:grid-cols-[minmax(0,1fr)_minmax(380px,0.9fr)]">
          <div class="space-y-4 px-5 py-5 lg:border-r lg:border-nya-divider">
            {#if selectedTemplate}
              <div><Input id="communications-email-subject" label="邮件主题" value={selectedTemplate.subject} maxlength={160} oninput={(event) => updateTemplate('subject', event.currentTarget instanceof HTMLInputElement ? event.currentTarget.value : '')} /><EmailVariableButtons fieldLabel="邮件主题" variables={variableRules.subject} oninsert={(variable) => insertVariable('subject', variable)} /></div>
              <div><Input id="communications-email-heading" label="内容标题" value={selectedTemplate.heading} maxlength={120} oninput={(event) => updateTemplate('heading', event.currentTarget instanceof HTMLInputElement ? event.currentTarget.value : '')} /><EmailVariableButtons fieldLabel="内容标题" variables={variableRules.heading} oninsert={(variable) => insertVariable('heading', variable)} /></div>
              <div><label for="communications-email-body" class="mb-1.5 block text-body-medium text-nya-text-primary">正文</label><textarea id="communications-email-body" value={selectedTemplate.body} oninput={(event) => updateTemplate('body', event.currentTarget.value)} maxlength="2400" rows="7" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea><EmailVariableButtons fieldLabel="正文" variables={variableRules.body} required={variableRules.required_body} oninsert={(variable) => insertVariable('body', variable)} /></div>
              {#if 'button_label' in selectedTemplate}<div><Input id="communications-email-button" label="操作按钮文字" value={selectedTemplate.button_label ?? ''} maxlength={48} oninput={(event) => updateTemplate('button_label', event.currentTarget instanceof HTMLInputElement ? event.currentTarget.value : '')} /><EmailVariableButtons fieldLabel="操作按钮文字" variables={variableRules.button_label} oninsert={(variable) => insertVariable('button_label', variable)} /></div>{/if}
              <div><label for="communications-email-footer" class="mb-1.5 block text-body-medium text-nya-text-primary">统一页脚</label><textarea id="communications-email-footer" bind:value={email.footer} maxlength="600" rows="3" class="w-full rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-body text-nya-text-primary focus:border-nya-primary focus:outline-none focus:ring-2 focus:ring-nya-primary/24"></textarea><EmailVariableButtons fieldLabel="统一页脚" variables={['site_name']} oninsert={(variable) => { const token = `{{${variable}}}`; email.footer = `${email.footer}${token}`; }} /></div>
            {/if}
          </div>
          <div class="min-w-0 bg-nya-surface-muted px-5 py-5">
            <div class="mb-3 flex flex-wrap items-center justify-between gap-2"><div class="inline-flex rounded-nya-sm bg-nya-surface p-1" aria-label="预览格式"><button type="button" onclick={() => (previewMode = 'html')} aria-pressed={previewMode === 'html'} class="rounded-nya-xs px-3 py-1.5 text-small font-semibold {previewMode === 'html' ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary'}">HTML</button><button type="button" onclick={() => (previewMode = 'text')} aria-pressed={previewMode === 'text'} class="rounded-nya-xs px-3 py-1.5 text-small font-semibold {previewMode === 'text' ? 'bg-nya-primary-soft text-nya-primary' : 'text-nya-text-secondary'}">纯文本</button></div><Button variant="secondary" size="sm" onclick={requestPreview} loading={previewing}><Eye size={14} /> 生成预览</Button></div>
            {#if preview}
              <p class="mb-2 truncate text-small font-semibold text-nya-text-primary" title={preview.subject}>{preview.subject}</p>
              {#if previewMode === 'html'}<iframe title={`${templateLabels[previewedTemplateID] ?? previewedTemplateID} HTML 邮件预览`} sandbox="" srcdoc={preview.html_body} class="h-[440px] w-full rounded-nya-sm border border-nya-border bg-white"></iframe>{:else}<pre class="h-[440px] overflow-auto whitespace-pre-wrap rounded-nya-sm border border-nya-border bg-nya-surface p-4 text-small text-nya-text-primary">{preview.text_body}</pre>{/if}
            {:else}<div class="flex h-[440px] items-center justify-center rounded-nya-sm border border-dashed border-nya-border-strong bg-nya-surface px-6 text-center text-small text-nya-text-tertiary">选择模板并生成预览；服务端会使用示例数据替换变量。</div>{/if}
            <div class="mt-4 border-t border-nya-divider pt-4"><Input id="communications-test-recipient" label="测试收件人" type="email" value={testRecipient} autocomplete="off" ignorePasswordManagers readonly disabled={!testEmailAvailable} placeholder="请先验证管理员邮箱" /><div class="mt-2"><Button variant="secondary" onclick={requestTest} loading={testing} disabled={!testEmailAvailable}><Send size={14} /> 发送测试邮件</Button></div>{#if testEmailAvailable}<p class="mt-2 text-micro text-nya-text-tertiary">仅可发送到当前管理员已验证邮箱。测试使用当前未保存草稿，收件人不会写入浏览器恢复存储。</p>{:else}<p class="mt-2 text-small text-nya-warning">当前管理员没有已验证邮箱，模板测试已禁用。</p>{/if}</div>
          </div>
        </div>
      {/if}

      <div class="flex items-center justify-end border-t border-nya-divider px-5 py-4"><Button type="submit" variant="primary" requiredCapability="admin_mutations" loading={saving}>保存沟通设置</Button></div>
    </form>
  {/if}
</section>

<ReauthenticationDialog bind:open={reauthOpen} {returnTo} description="保存沟通设置或发送测试邮件前需要验证近期身份" onauthenticated={retryPendingAction} onbeforeprovider={persistProviderDraft} />
