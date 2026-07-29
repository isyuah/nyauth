import { get } from 'svelte/store';
import { afterEach, describe, expect, it } from 'vitest';
import { addToast, clearToasts, dismissToast, toastStore } from './toast';

afterEach(() => clearToasts());

describe('toast store', () => {
  it('adds typed messages and dismisses only the selected message', () => {
    const successID = addToast('success', '保存成功', 0);
    const errorID = addToast('error', '保存失败', 0);

    expect(get(toastStore)).toEqual([
      { id: successID, type: 'success', message: '保存成功' },
      { id: errorID, type: 'error', message: '保存失败' },
    ]);

    dismissToast(successID);
    expect(get(toastStore)).toEqual([
      { id: errorID, type: 'error', message: '保存失败' },
    ]);
  });

  it('clears every visible message', () => {
    addToast('warning', '需要注意', 0);
    addToast('info', '处理中', 0);

    clearToasts();
    expect(get(toastStore)).toEqual([]);
  });
});
