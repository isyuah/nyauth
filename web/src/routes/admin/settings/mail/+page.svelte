<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type RegistrationMode } from '$lib/api';
  import MailSettingsPanel from '$lib/components/admin/MailSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
  import Button from '$lib/components/ui/Button.svelte';

  let registrationMode = $state<RegistrationMode | null>(null);
  let registrationError = $state('');

  async function loadRegistrationMode() {
    registrationError = '';
    try {
      registrationMode = (await api.admin.getRegistrationSettings()).mode;
    } catch (cause) {
      registrationMode = null;
      registrationError = cause instanceof Error ? cause.message : '注册设置加载失败';
    }
  }

  onMount(loadRegistrationMode);
</script>

<svelte:head><title>邮件设置 - Nya</title></svelte:head>
<SettingsPageHeader title="邮件设置" description="测试、激活和回滚运行时 SMTP 配置" />
<div class="mt-4">
{#if registrationError}
  <div class="mb-4 flex items-center justify-between gap-3 rounded-nya-sm bg-nya-warning-soft px-3 py-2">
    <p class="text-small text-nya-warning">无法确认注册模式，因此暂不能禁用邮件：{registrationError}</p>
    <Button variant="ghost" size="sm" onclick={loadRegistrationMode}>重试</Button>
  </div>
{/if}
<MailSettingsPanel {registrationMode} />
</div>
