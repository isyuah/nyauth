<script lang="ts">
  import CommunicationsSettingsPanel from '$lib/components/admin/CommunicationsSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<div class="space-y-5">
  <SettingsPageHeader title="沟通设置" description="管理全站横幅与事务邮件模板" />
  <CommunicationsSettingsPanel />
</div>
