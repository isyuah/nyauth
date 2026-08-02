import type { Branding, PrimaryTextColor, ResolvedTheme, Theme } from './api';

export const DEFAULT_PRIMARY_COLOR = '#704DE8';

type RGB = { r: number; g: number; b: number };

function channel(value: number): number {
  return Math.max(0, Math.min(255, Math.round(value)));
}

export function normalizeHexColor(value: string): string | null {
  const normalized = value.trim().toUpperCase();
  return /^#[0-9A-F]{6}$/.test(normalized) ? normalized : null;
}

export function hexToRGB(value: string): RGB {
  const normalized = normalizeHexColor(value);
  if (!normalized) throw new TypeError('color must use #RRGGBB format');
  return {
    r: Number.parseInt(normalized.slice(1, 3), 16),
    g: Number.parseInt(normalized.slice(3, 5), 16),
    b: Number.parseInt(normalized.slice(5, 7), 16),
  };
}

function rgbToHex({ r, g, b }: RGB): string {
  return `#${[r, g, b].map((value) => channel(value).toString(16).padStart(2, '0')).join('')}`.toUpperCase();
}

export function mixColors(foreground: string, background: string, backgroundWeight: number): string {
  if (backgroundWeight < 0 || backgroundWeight > 1) throw new RangeError('background weight must be between 0 and 1');
  const front = hexToRGB(foreground);
  const back = hexToRGB(background);
  return rgbToHex({
    r: front.r * (1 - backgroundWeight) + back.r * backgroundWeight,
    g: front.g * (1 - backgroundWeight) + back.g * backgroundWeight,
    b: front.b * (1 - backgroundWeight) + back.b * backgroundWeight,
  });
}

function linearChannel(value: number): number {
  const scaled = value / 255;
  return scaled <= 0.04045 ? scaled / 12.92 : ((scaled + 0.055) / 1.055) ** 2.4;
}

export function relativeLuminance(value: string): number {
  const { r, g, b } = hexToRGB(value);
  return 0.2126 * linearChannel(r) + 0.7152 * linearChannel(g) + 0.0722 * linearChannel(b);
}

export function contrastRatio(first: string, second: string): number {
  const high = Math.max(relativeLuminance(first), relativeLuminance(second));
  const low = Math.min(relativeLuminance(first), relativeLuminance(second));
  return (high + 0.05) / (low + 0.05);
}

export function readableTextColor(background: string): '#FFFFFF' | '#111111' {
  return contrastRatio(background, '#FFFFFF') >= contrastRatio(background, '#111111') ? '#FFFFFF' : '#111111';
}

export function selectedTextColor(background: string, preference: PrimaryTextColor): '#FFFFFF' | '#111111' {
  if (preference === 'white') return '#FFFFFF';
  if (preference === 'black') return '#111111';
  return readableTextColor(background);
}

export function resolveTheme(preference: Theme, systemDark: boolean): ResolvedTheme {
  return preference === 'system' ? (systemDark ? 'dark' : 'light') : preference;
}

export function primaryPalette(
  primaryColor: string,
  theme: ResolvedTheme,
  primaryTextColor: PrimaryTextColor = 'auto',
): Record<string, string> {
  const primary = normalizeHexColor(primaryColor) ?? DEFAULT_PRIMARY_COLOR;
  const dark = theme === 'dark';
  const canvas = dark ? '#171720' : '#FFFFFF';
  const rgb = hexToRGB(primary);
  return {
    '--nya-primary': primary,
    '--nya-primary-rgb': `${rgb.r} ${rgb.g} ${rgb.b}`,
    '--nya-primary-hover': mixColors(primary, dark ? '#FFFFFF' : '#000000', dark ? 0.12 : 0.10),
    '--nya-primary-active': mixColors(primary, dark ? '#FFFFFF' : '#000000', dark ? 0.20 : 0.18),
    '--nya-primary-soft': mixColors(primary, canvas, dark ? 0.76 : 0.88),
    '--nya-primary-softer': mixColors(primary, canvas, dark ? 0.86 : 0.94),
    '--nya-primary-border': mixColors(primary, canvas, dark ? 0.58 : 0.68),
    '--nya-primary-contrast': selectedTextColor(primary, primaryTextColor),
  };
}

export function logoForTheme(branding: Branding, theme: ResolvedTheme): string {
  return (theme === 'dark' ? branding.dark_logo_url : branding.light_logo_url)
    || (theme === 'dark' ? branding.light_logo_url : branding.dark_logo_url)
    || '/logo.png';
}

export function applyThemeToDocument(branding: Branding, theme: ResolvedTheme, documentRef: Document = document): void {
  const root = documentRef.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  for (const [name, value] of Object.entries(primaryPalette(branding.primary_color, theme, branding.primary_text_color))) {
    root.style.setProperty(name, value);
  }
  let favicon = documentRef.querySelector<HTMLLinkElement>('link[data-runtime-favicon]');
  if (!favicon) {
    favicon = documentRef.createElement('link');
    favicon.rel = 'icon';
    favicon.dataset.runtimeFavicon = 'true';
    documentRef.head.append(favicon);
  }
  favicon.href = branding.favicon_url || '/favicon.ico';
}
