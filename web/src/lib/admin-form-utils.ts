export function parseLineList(value: string): string[] {
  return value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
}

export function parseTokenList(value: string): string[] {
  return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
}

export function formatStringMetadata(metadata?: Record<string, string>): string {
  return JSON.stringify(metadata || {}, null, 2);
}

export function parseStringMetadata(value: string): Record<string, string> {
  const trimmed = value.trim();
  if (!trimmed) return {};

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error('Metadata 必须是有效的 JSON 对象。');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Metadata 必须是字符串键值组成的 JSON 对象。');
  }
  for (const entry of Object.values(parsed)) {
    if (typeof entry !== 'string') {
      throw new Error('Metadata 的所有值都必须是字符串。');
    }
  }
  return parsed as Record<string, string>;
}
