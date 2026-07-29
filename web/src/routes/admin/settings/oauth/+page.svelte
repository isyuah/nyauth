<script lang="ts">
  import OAuthSettingsPanel from '$lib/components/admin/OAuthSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>OAuth 客户端 - Nya</title></svelte:head>
<SettingsPageHeader title="OAuth 客户端" description="管理客户端注册类型、Grant、Scope 与 URI 上限" />
<div class="mt-4"><OAuthSettingsPanel /></div>
