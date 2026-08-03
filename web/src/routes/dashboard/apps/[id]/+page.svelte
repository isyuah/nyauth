<script lang="ts">
  import { page } from '$app/stores';
  import OAuthClientInsights from '$lib/components/oauth/OAuthClientInsights.svelte';
</script>

<OAuthClientInsights clientID={$page.params.id || ''} />
