<script lang="ts">
  import ObservabilitySettingsPanel from '$lib/components/admin/ObservabilitySettingsPanel.svelte';
  import SettingsPageHeader from '$lib/components/admin/SettingsPageHeader.svelte';
</script>

<svelte:head><title>可观测性 - Nya</title></svelte:head>
<SettingsPageHeader title="可观测性" description="管理日志级别、运营告警阈值与 OTLP Metrics 导出" />
<div class="mt-4"><ObservabilitySettingsPanel /></div>
