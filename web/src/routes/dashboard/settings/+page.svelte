<script lang="ts">
  import Card from '$lib/components/ui/Card.svelte';
  import { Settings } from 'lucide-svelte';
</script>

<svelte:head><title>设置 - Nya</title></svelte:head>

<div style="margin-bottom: 24px;">
  <h1 style="font-size: 24px; font-weight: 700; color: var(--nya-text-primary); margin: 0;">设置</h1>
  <p style="font-size: 14px; color: var(--nya-text-secondary); margin-top: 4px;">管理你的账户偏好</p>
</div>

<Card>
  <div class="flex items-center gap-3" style="padding: 12px 0;">
    <Settings size={20} style="color: var(--nya-text-tertiary);" />
    <p style="font-size: 14px; color: var(--nya-text-tertiary);">更多设置功能将在后续版本中添加。</p>
  </div>
</Card>
