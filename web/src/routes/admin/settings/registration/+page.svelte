<script lang="ts">
  import RegistrationSettingsPanel from '$lib/components/admin/RegistrationSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>注册设置 - Nya</title></svelte:head>
<SettingsPageHeader title="注册设置" description="控制开放注册、邀请制与邮箱验证生命周期" />
<div class="mt-4"><RegistrationSettingsPanel /></div>
