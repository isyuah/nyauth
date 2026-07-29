<script lang="ts">
  import LifecycleSettingsPanel from '$lib/components/admin/LifecycleSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>生命周期 - Nya</title></svelte:head>
<SettingsPageHeader title="生命周期" description="管理会话、近期认证与审计数据保留期限" />
<div class="mt-4"><LifecycleSettingsPanel /></div>
