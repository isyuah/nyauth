<script lang="ts">
  import { announcementStore, isSafeAnnouncementLink } from '$lib/announcement';
  import type { AnnouncementSeverity } from '$lib/api';
  import { AlertCircle, AlertTriangle, Info, X } from 'lucide-svelte';

  let announcement = $derived($announcementStore.value.announcement);
  let visible = $derived($announcementStore.initialized && announcement !== null && !$announcementStore.dismissed);
  let safeLink = $derived(resolveLink(announcement?.link_url));

  const styles: Record<AnnouncementSeverity, string> = {
    info: 'border-nya-info/25 bg-nya-info-soft text-nya-info',
    warning: 'border-nya-warning/25 bg-nya-warning-soft text-nya-warning',
    critical: 'border-nya-danger/25 bg-nya-danger-soft text-nya-danger',
  };

  function resolveLink(raw?: string): { href: string; external: boolean } | null {
    if (!raw || !isSafeAnnouncementLink(raw)) return null;
    if (raw.startsWith('/') && !raw.startsWith('//')) return { href: raw, external: false };
    try {
      const parsed = new URL(raw);
      const sameOrigin = typeof window !== 'undefined' && parsed.origin === window.location.origin;
      return { href: parsed.toString(), external: !sameOrigin };
    } catch {
      return null;
    }
  }
</script>

{#if visible && announcement}
  <aside class="relative z-[71] flex min-h-11 items-start justify-center gap-3 border-b px-4 py-2 text-small {styles[announcement.severity]}" role={announcement.severity === 'critical' ? 'alert' : 'status'} aria-live={announcement.severity === 'critical' ? 'assertive' : 'polite'}>
    {#if announcement.severity === 'critical'}<AlertCircle size={16} class="mt-0.5 shrink-0" />{:else if announcement.severity === 'warning'}<AlertTriangle size={16} class="mt-0.5 shrink-0" />{:else}<Info size={16} class="mt-0.5 shrink-0" />{/if}
    <div class="min-w-0 text-center sm:flex sm:items-baseline sm:gap-2 sm:text-left">
      <strong class="font-semibold">{announcement.title}</strong>
      <span class="ml-1 sm:ml-0">{announcement.message}</span>
      {#if safeLink && announcement.link_label}
        <a href={safeLink.href} target={safeLink.external ? '_blank' : undefined} rel={safeLink.external ? 'noopener noreferrer' : undefined} class="ml-1 whitespace-nowrap font-semibold underline underline-offset-2 sm:ml-0">{announcement.link_label}</a>
      {/if}
    </div>
    {#if announcement.dismissible}
      <button type="button" onclick={() => announcementStore.dismiss()} class="shrink-0 rounded-nya-xs p-0.5 hover:bg-black/5" aria-label="关闭站点公告"><X size={15} /></button>
    {/if}
  </aside>
{/if}
