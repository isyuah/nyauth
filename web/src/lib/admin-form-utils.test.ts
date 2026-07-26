import { describe, expect, it } from 'vitest';
import { formatStringMetadata, parseLineList, parseStringMetadata, parseTokenList } from './admin-form-utils';

describe('admin form utilities', () => {
  it('normalizes line and token lists', () => {
    expect(parseLineList(' https://a.example/cb \n\nhttps://b.example/cb ')).toEqual([
      'https://a.example/cb',
      'https://b.example/cb',
    ]);
    expect(parseTokenList('openid, profile\nemail')).toEqual(['openid', 'profile', 'email']);
  });

  it('round trips string metadata', () => {
    const metadata = { environment: 'production', owner: 'platform' };
    expect(parseStringMetadata(formatStringMetadata(metadata))).toEqual(metadata);
  });

  it('rejects non-object or non-string metadata', () => {
    expect(() => parseStringMetadata('[]')).toThrow(/JSON 对象/);
    expect(() => parseStringMetadata('{"risk": 3}')).toThrow(/字符串/);
  });
});
