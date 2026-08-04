<script lang="ts">
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { api, type Announcement } from '$lib/api';
  import { notificationCenterStore } from '$lib/notification-center';
  import ResourceState from '$lib/components/ui/ResourceState.svelte';
  import { toast } from '$lib/toast';
  import { ArrowLeft, ExternalLink } from 'lucide-svelte';
  let item = $state<Announcement | null>(null); let loading = $state(true); let error = $state('');
  async function load() {
    loading = true; error = '';
    try {
      const id = $page.params.id;
      if (!id) throw new Error('公告 ID 无效');
      item = await api.getAnnouncement(id);
      if (!item.read) {
        try { await api.markAnnouncementRead(item.id); item.read = true; await notificationCenterStore.refresh().catch(() => {}); }
        catch (cause) { toast.error(cause instanceof Error ? cause.message : '公告已读状态保存失败'); }
      }
    } catch (cause) { error = cause instanceof Error ? cause.message : '公告加载失败'; }
    finally { loading = false; }
  }
  onMount(load);
</script>
<div class="mx-auto max-w-3xl"><a href="/dashboard/messages?tab=announcements" class="mb-4 inline-flex items-center gap-1 text-body text-nya-text-secondary hover:text-nya-primary"><ArrowLeft size={15}/>返回消息中心</a><ResourceState {loading} {error} onretry={load}>{#if item}<article class="rounded-nya-card border border-nya-border bg-nya-surface p-6 md:p-8"><div class="mb-5 border-b border-nya-divider pb-5"><h1 class="text-2xl font-bold text-nya-text-primary">{item.title}</h1>{#if item.summary}<p class="mt-2 text-body text-nya-text-secondary">{item.summary}</p>{/if}<time class="mt-3 block text-small text-nya-text-tertiary">{new Intl.DateTimeFormat('zh-CN',{dateStyle:'long',timeStyle:'short'}).format(new Date(item.published_at||item.updated_at))}</time></div><div class="announcement-markdown text-body leading-7 text-nya-text-primary">{@html item.body_html || ''}</div>{#if item.link_url}<a href={item.link_url} class="mt-6 inline-flex items-center gap-1 font-medium text-nya-primary hover:underline">继续查看 <ExternalLink size={14}/></a>{/if}</article>{/if}</ResourceState></div>
<style>:global(.announcement-markdown p){margin:0 0 1rem}:global(.announcement-markdown h1),:global(.announcement-markdown h2),:global(.announcement-markdown h3){margin:1.5rem 0 .75rem;font-weight:700}:global(.announcement-markdown ul),:global(.announcement-markdown ol){margin:0 0 1rem;padding-left:1.5rem}:global(.announcement-markdown ul){list-style:disc}:global(.announcement-markdown ol){list-style:decimal}:global(.announcement-markdown a){color:var(--nya-primary);text-decoration:underline}</style>
