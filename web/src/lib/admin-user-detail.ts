import { getContext, setContext } from 'svelte';
import type { AdminUserOverview, User } from '$lib/api';

const contextKey = Symbol('admin-user-detail');

export interface AdminUserDetailContext {
  readonly userID: string;
  readonly returnTo: string;
  readonly overview: AdminUserOverview | null;
  readonly loading: boolean;
  readonly error: string;
  reload(): Promise<void>;
  updateUser(user: User): void;
}

export function provideAdminUserDetailContext(context: AdminUserDetailContext): void {
  setContext(contextKey, context);
}

export function useAdminUserDetailContext(): AdminUserDetailContext {
  const context = getContext<AdminUserDetailContext>(contextKey);
  if (!context) throw new Error('admin user detail context is unavailable');
  return context;
}
