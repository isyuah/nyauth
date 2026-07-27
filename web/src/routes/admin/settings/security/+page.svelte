<script lang="ts">
  import SecuritySettingsPanel from '$lib/components/admin/SecuritySettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>登录安全设置 - Nya</title></svelte:head>
<SettingsPageHeader title="登录安全设置" description="管理 TOTP、Passkey 和管理员 MFA 策略" />
<div class="mt-4"><SecuritySettingsPanel /></div>
