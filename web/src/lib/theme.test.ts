import { describe, expect, it } from 'vitest';
import { contrastRatio, mixColors, normalizeHexColor, primaryPalette, readableTextColor, resolveTheme, selectedTextColor } from './theme';

describe('theme utilities', () => {
  it('normalizes strict six-digit colors', () => {
    expect(normalizeHexColor(' #704de8 ')).toBe('#704DE8');
    expect(normalizeHexColor('#fff')).toBeNull();
    expect(normalizeHexColor('704DE8')).toBeNull();
  });

  it('resolves browser-local and system preferences', () => {
    expect(resolveTheme('dark', false)).toBe('dark');
    expect(resolveTheme('light', true)).toBe('light');
    expect(resolveTheme('system', true)).toBe('dark');
    expect(resolveTheme('system', false)).toBe('light');
  });

  it('creates stable palette colors and accessible button text', () => {
    const palette = primaryPalette('#704DE8', 'light');
    expect(palette['--nya-primary']).toBe('#704DE8');
    expect(palette['--nya-primary-rgb']).toBe('112 77 232');
    expect(palette).toMatchObject({
      '--nya-primary-hover': '#6545D1',
      '--nya-primary-active': '#5C3FBE',
      '--nya-primary-soft': '#EEEAFC',
      '--nya-primary-softer': '#F6F4FE',
      '--nya-primary-border': '#D1C6F8',
      '--nya-primary-contrast': '#FFFFFF',
    });
    expect(contrastRatio(palette['--nya-primary'], palette['--nya-primary-contrast'])).toBeGreaterThanOrEqual(4.5);
    expect(readableTextColor('#FFFFFF')).toBe('#111111');
    expect(readableTextColor('#000000')).toBe('#FFFFFF');
    expect(selectedTextColor('#F6D365', 'white')).toBe('#FFFFFF');
    expect(selectedTextColor('#111111', 'black')).toBe('#111111');
    expect(primaryPalette('#F6D365', 'light', 'white')['--nya-primary-contrast']).toBe('#FFFFFF');
  });

  it('mixes colors without accepting out-of-range weights', () => {
    expect(mixColors('#000000', '#FFFFFF', 0.5)).toBe('#808080');
    expect(() => mixColors('#000000', '#FFFFFF', 2)).toThrow(RangeError);
  });
});
