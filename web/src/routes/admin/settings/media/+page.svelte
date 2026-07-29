<script lang="ts">
  import MediaSettingsPanel from '$lib/components/admin/MediaSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>媒体存储 - Nya</title></svelte:head>
<SettingsPageHeader title="媒体存储" description="动态配置私有对象存储，并安全迁移现有头像" />
<div class="mt-4"><MediaSettingsPanel /></div>
