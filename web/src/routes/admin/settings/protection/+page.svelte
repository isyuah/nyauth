<script lang="ts">
  import ProtectionSettingsPanel from '$lib/components/admin/ProtectionSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>访问保护 - Nya</title></svelte:head>
<SettingsPageHeader title="访问保护" description="动态调整登录、账户、头像与 SMTP 管理限流" />
<div class="mt-4"><ProtectionSettingsPanel /></div>
