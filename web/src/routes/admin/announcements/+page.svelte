<script lang="ts">
  import { onMount } from 'svelte';
  import { page } from '$app/stores';
  import { api, isRecentAuthenticationError, type Announcement, type AnnouncementAudience, type AnnouncementInput, type CommunicationSeverity } from '$lib/api';
  import PageHeader from '$lib/components/layout/PageHeader.svelte';
  import Pagination from '$lib/components/data-display/Pagination.svelte';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Input from '$lib/components/ui/Input.svelte';
  import Select from '$lib/components/ui/Select.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import Switch from '$lib/components/ui/Switch.svelte';
  import DateTimeRangePicker from '$lib/components/ui/DateTimeRangePicker.svelte';
  import ReauthenticationDialog from '$lib/components/account/ReauthenticationDialog.svelte';
  import { toast } from '$lib/toast';
  import { Archive, Eye, Megaphone, Pencil, Plus, Send } from 'lucide-svelte';

  type PendingAction = { kind: 'save' } | { kind: 'publish'; item: Announcement } | { kind: 'archive'; item: Announcement };
  const severityOptions = [{ value: 'info', label: '信息' }, { value: 'warning', label: '警告' }, { value: 'critical', label: '重要' }];
  const audienceOptions = [{ value: 'authenticated', label: '所有已登录用户' }, { value: 'admins', label: '仅管理员' }];
  const statusOptions = [{ value: '', label: '全部状态' }, { value: 'draft', label: '草稿' }, { value: 'published', label: '已发布' }, { value: 'archived', label: '已归档' }];
  const emptyForm = (): AnnouncementInput => ({ severity: 'info', audience: 'authenticated', title: '', summary: '', body_markdown: '', link_url: '', pinned: false, starts_at: null, ends_at: null });
  const providerDraftKey = 'nyauth:reauth:announcement-action';

  const pageSize = 20;
  let items = $state<Announcement[]>([]); let loading = $state(true); let error = $state(''); let query = $state(''); let status = $state(''); let currentPage = $state(1); let total = $state(0);
  let editorOpen = $state(false); let editTarget = $state<Announcement | null>(null); let form = $state<AnnouncementInput>(emptyForm()); let startsAt = $state(''); let endsAt = $state(''); let saving = $state(false); let formError = $state('');
  let previewHTML = $state(''); let previewing = $state(false); let reauthOpen = $state(false); let pendingAction = $state<PendingAction | null>(null);
  let returnTo = $derived(`${$page.url.pathname}${$page.url.search}`);

  function toLocal(value?: string) { if (!value) return ''; const d = new Date(value); const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000); return local.toISOString().slice(0, 16); }
  function toISO(value: string) { return value ? new Date(value).toISOString() : null; }
  function statusLabel(item: Announcement) { if (item.status === 'published' && item.starts_at && new Date(item.starts_at) > new Date()) return '计划发布'; return item.status === 'draft' ? '草稿' : item.status === 'archived' ? '已归档' : '已发布'; }
  function statusClass(item: Announcement) { return item.status === 'published' ? 'bg-nya-success-soft text-nya-success' : item.status === 'archived' ? 'bg-nya-surface-muted text-nya-text-tertiary' : 'bg-nya-warning-soft text-nya-warning'; }
  function buildInput(): AnnouncementInput { return { ...form, starts_at: toISO(startsAt), ends_at: toISO(endsAt), title: form.title.trim(), summary: form.summary.trim(), body_markdown: form.body_markdown.trim(), link_url: form.link_url.trim() }; }

  async function load() {
    loading = true; error = '';
    try {
      const result = await api.admin.getAnnouncements({ page: currentPage, pageSize, q: query.trim(), status });
      items = result.items || []; total = result.total;
      if (currentPage > Math.max(1, result.total_pages)) { currentPage = Math.max(1, result.total_pages); await load(); }
    } catch (cause) { error = cause instanceof Error ? cause.message : '公告列表加载失败'; }
    finally { loading = false; }
  }
  async function applyFilters() { currentPage = 1; await load(); }
  async function changePage(value: number) { currentPage = value; await load(); }
  function create() { editTarget=null;form=emptyForm();startsAt='';endsAt='';previewHTML='';formError='';editorOpen=true; }
  function edit(item: Announcement) { editTarget=item;form={severity:item.severity,audience:item.audience,title:item.title,summary:item.summary,body_markdown:item.body_markdown||'',link_url:item.link_url||'',pinned:item.pinned,starts_at:item.starts_at||null,ends_at:item.ends_at||null};startsAt=toLocal(item.starts_at);endsAt=toLocal(item.ends_at);previewHTML='';formError='';editorOpen=true; }

  async function execute(action: PendingAction, allowReauth = true) {
    formError='';
    try {
      if (action.kind === 'save') { saving=true; if (editTarget) await api.admin.updateAnnouncement(editTarget.id, editTarget.revision, buildInput()); else await api.admin.createAnnouncement(buildInput()); editorOpen=false; toast.success(editTarget?'公告已保存':'草稿已创建'); }
      else if (action.kind === 'publish') { await api.admin.publishAnnouncement(action.item.id, action.item.revision); toast.success('公告已发布'); }
      else { await api.admin.archiveAnnouncement(action.item.id, action.item.revision); toast.success('公告已归档'); }
      pendingAction=null; await load();
    } catch (cause) {
      if (allowReauth && isRecentAuthenticationError(cause)) { pendingAction=action; reauthOpen=true; return; }
      formError=cause instanceof Error?cause.message:'公告操作失败'; toast.error(formError);
    } finally { saving=false; }
  }

  async function preview() { previewing=true;formError='';try{previewHTML=(await api.admin.previewAnnouncement(form.body_markdown)).body_html;}catch(cause){formError=cause instanceof Error?cause.message:'预览失败';}finally{previewing=false;} }
  function persistProviderAction() { if (!pendingAction) return; sessionStorage.setItem(providerDraftKey, JSON.stringify({ pendingAction, editTarget, form, startsAt, endsAt })); }
  onMount(() => { void load(); try { const raw=sessionStorage.getItem(providerDraftKey); sessionStorage.removeItem(providerDraftKey); if(raw){const saved=JSON.parse(raw);pendingAction=saved.pendingAction;editTarget=saved.editTarget;form=saved.form;startsAt=saved.startsAt||'';endsAt=saved.endsAt||'';editorOpen=pendingAction?.kind==='save';reauthOpen=true;} } catch { sessionStorage.removeItem(providerDraftKey); } });
</script>

<div class="space-y-5">
  <PageHeader title="公告管理" description="创建可检索、可计划发布并保留已读状态的站内公告">
    {#snippet action()}<Button size="sm" onclick={create}><Plus size={15}/>新建公告</Button>{/snippet}
  </PageHeader>
  <div class="grid gap-3 rounded-nya-card border border-nya-border bg-nya-surface p-4 sm:grid-cols-[1fr_180px_auto]">
    <Input bind:value={query} placeholder="搜索标题或摘要" ignorePasswordManagers />
    <Select bind:value={status} options={statusOptions} placeholder="全部状态" />
    <Button variant="secondary" onclick={applyFilters}>筛选</Button>
  </div>
  <ResourceState {loading} {error} empty={items.length===0} emptyTitle="暂无公告" emptyDescription="先创建一条草稿，再预览并发布" onretry={load}>
    <div>
      <div class="overflow-hidden rounded-nya-card border border-nya-border bg-nya-surface">
        {#each items as item (item.id)}
          <article class="flex flex-col gap-3 border-b border-nya-divider p-4 last:border-0 sm:flex-row sm:items-center">
            <div class="min-w-0 flex-1"><div class="flex flex-wrap items-center gap-2"><h2 class="truncate font-semibold text-nya-text-primary">{item.title||'未命名草稿'}</h2><span class="rounded-full px-2 py-0.5 text-[11px] font-medium {statusClass(item)}">{statusLabel(item)}</span>{#if item.pinned}<span class="text-[11px] text-nya-primary">置顶</span>{/if}</div><p class="mt-1 truncate text-body text-nya-text-secondary">{item.summary||'暂无摘要'}</p><p class="mt-1 text-small text-nya-text-tertiary">{item.audience==='admins'?'仅管理员':'所有已登录用户'} · 更新于 {new Intl.DateTimeFormat('zh-CN',{dateStyle:'medium',timeStyle:'short'}).format(new Date(item.updated_at))}</p></div>
            <div class="flex shrink-0 gap-2"><Button variant="secondary" size="sm" onclick={()=>edit(item)}><Pencil size={14}/>编辑</Button>{#if item.status==='draft'}<Button size="sm" onclick={()=>execute({kind:'publish',item})}><Send size={14}/>发布</Button>{/if}{#if item.status==='published'}<Button variant="ghost" size="sm" onclick={()=>execute({kind:'archive',item})}><Archive size={14}/>归档</Button>{/if}</div>
          </article>
        {/each}
      </div>
      <Pagination bind:page={currentPage} {pageSize} {total} onchange={changePage} />
    </div>
  </ResourceState>
</div>

<Modal bind:open={editorOpen} size="lg" title={editTarget?'编辑公告':'新建公告'} description="草稿不会向用户展示；发布前可先预览正文">
  <div class="space-y-4">
    <div class="grid gap-4 sm:grid-cols-2"><Input label="标题" maxlength={120} bind:value={form.title}/><Input label="摘要" maxlength={240} bind:value={form.summary}/><Select label="级别" bind:value={form.severity} options={severityOptions}/><Select label="受众" bind:value={form.audience} options={audienceOptions}/></div>
    <Input label="站内或 HTTPS 链接（可选）" bind:value={form.link_url} placeholder="/profile/security" ignorePasswordManagers />
    <DateTimeRangePicker label="展示时间" mode="schedule" bind:from={startsAt} bind:to={endsAt}/>
    <Switch bind:checked={form.pinned} label="置顶公告" help="置顶公告在公告中心优先显示" />
    <label class="block"><span class="mb-1.5 block text-body-medium text-nya-text-primary">正文（安全 Markdown）</span><textarea bind:value={form.body_markdown} rows="10" maxlength="20000" class="w-full resize-y rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 font-mono text-small text-nya-text-primary outline-none transition focus:border-nya-primary focus:ring-2 focus:ring-nya-primary/20" placeholder="支持标题、列表、强调和安全链接；不支持 HTML 或图片"></textarea></label>
    {#if formError}<p class="text-small text-nya-danger" role="alert">{formError}</p>{/if}
    {#if previewHTML}<div class="rounded-nya-md border border-nya-border bg-nya-surface-muted p-4"><div class="mb-2 flex items-center gap-2 text-small font-semibold text-nya-text-secondary"><Eye size={14}/>用户预览</div><div class="announcement-preview text-body text-nya-text-primary">{@html previewHTML}</div></div>{/if}
    <div class="flex justify-end gap-2"><Button variant="secondary" loading={previewing} onclick={preview}><Eye size={14}/>预览</Button><Button loading={saving} onclick={()=>execute({kind:'save'})}>{editTarget?'保存修改':'创建草稿'}</Button></div>
  </div>
</Modal>

<ReauthenticationDialog bind:open={reauthOpen} {returnTo} description="修改或发布公告前需要验证近期身份" onauthenticated={async()=>{if(pendingAction)await execute(pendingAction,false);}} onbeforeprovider={persistProviderAction} />

<style>:global(.announcement-preview p){margin:0 0 .75rem}:global(.announcement-preview ul),:global(.announcement-preview ol){padding-left:1.25rem}:global(.announcement-preview a){color:var(--nya-primary);text-decoration:underline}</style>
