<script lang="ts">
  import HumanVerificationSettingsPanel from '$lib/components/admin/HumanVerificationSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>人机验证 - Nya</title></svelte:head>
<SettingsPageHeader title="人机验证" description="配置 Cloudflare Turnstile 与公开入口的自动化滥用防护" />
<div class="mt-4"><HumanVerificationSettingsPanel /></div>
