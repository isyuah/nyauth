<script lang="ts">
  import BrandingSettingsPanel from '$lib/components/admin/BrandingSettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>品牌设置 - Nya</title></svelte:head>
<SettingsPageHeader title="品牌设置" description="配置站点名称和由 Nyauth 管理的品牌标识" />
<div class="mt-4"><BrandingSettingsPanel /></div>
