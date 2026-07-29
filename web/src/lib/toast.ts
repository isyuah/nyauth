import { writable } from 'svelte/store';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastMessage {
  id: number;
  type: ToastType;
  message: string;
}

const defaultDurations: Record<ToastType, number> = {
  success: 4_000,
  error: 10_000,
  warning: 8_000,
  info: 5_000,
};

let nextID = 0;
const timers = new Map<number, ReturnType<typeof setTimeout>>();

export const toastStore = writable<ToastMessage[]>([]);

export function dismissToast(id: number) {
  const timer = timers.get(id);
  if (timer) clearTimeout(timer);
  timers.delete(id);
  toastStore.update((messages) => messages.filter((message) => message.id !== id));
}

export function clearToasts() {
  for (const timer of timers.values()) clearTimeout(timer);
  timers.clear();
  toastStore.set([]);
}

export function addToast(type: ToastType, message: string, duration = defaultDurations[type]): number {
  const id = ++nextID;
  toastStore.update((messages) => [...messages, { id, type, message }]);
  if (duration > 0) {
    timers.set(id, setTimeout(() => dismissToast(id), duration));
  }
  return id;
}

export const toast = {
  success: (message: string, duration?: number) => addToast('success', message, duration),
  error: (message: string, duration?: number) => addToast('error', message, duration),
  warning: (message: string, duration?: number) => addToast('warning', message, duration),
  info: (message: string, duration?: number) => addToast('info', message, duration),
};
