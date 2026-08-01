<script lang="ts">
  import Input from '$lib/components/ui/Input.svelte';

  let {
    idPrefix,
    name = $bindable(''),
    homepageURI = $bindable(''),
    privacyPolicyURI = $bindable(''),
    termsOfServiceURI = $bindable(''),
  }: {
    idPrefix: string;
    name: string;
    homepageURI: string;
    privacyPolicyURI: string;
    termsOfServiceURI: string;
  } = $props();
</script>

<div class="space-y-4">
  <Input id={`${idPrefix}-name`} label="应用名称" bind:value={name} required placeholder="我的应用" maxlength={128} />
  <div class="grid gap-4 sm:grid-cols-2">
    <Input id={`${idPrefix}-homepage-uri`} label="应用主页" bind:value={homepageURI} type="url" inputmode="url" placeholder="https://app.example.com" help="授权页上可供用户核对应用身份。" />
    <Input id={`${idPrefix}-privacy-policy-uri`} label="隐私政策" bind:value={privacyPolicyURI} type="url" inputmode="url" placeholder="https://app.example.com/privacy" help="公开可访问的 HTTPS 隐私政策页面。" />
  </div>
  <Input id={`${idPrefix}-terms-of-service-uri`} label="服务条款" bind:value={termsOfServiceURI} type="url" inputmode="url" placeholder="https://app.example.com/terms" help="公开可访问的 HTTPS 服务条款页面。" />
</div>
