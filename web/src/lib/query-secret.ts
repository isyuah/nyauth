export function takeQuerySecret(name: string): string {
  if (typeof window === 'undefined') return '';

  const url = new URL(window.location.href);
  const value = url.searchParams.get(name) || '';
  if (!url.searchParams.has(name)) return value;

  url.searchParams.delete(name);
  window.history.replaceState(window.history.state, '', `${url.pathname}${url.search}${url.hash}`);
  return value;
}
