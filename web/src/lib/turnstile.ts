export interface TurnstileRenderOptions {
  sitekey: string;
  action: string;
  theme?: 'auto' | 'light' | 'dark';
  size?: 'normal' | 'compact' | 'flexible';
  appearance?: 'always' | 'execute' | 'interaction-only';
  callback: (token: string) => void;
  'expired-callback': () => void;
  'timeout-callback': () => void;
  'error-callback': (code?: string) => boolean | void;
}

export interface TurnstileAPI {
  render(container: HTMLElement, options: TurnstileRenderOptions): string;
  reset(widgetId: string): void;
  remove(widgetId: string): void;
}

export type TurnstileWidgetMode = 'managed' | 'non-interactive' | 'invisible';

export interface TurnstilePresentation {
  appearance: NonNullable<TurnstileRenderOptions['appearance']>;
  reserveSpace: boolean;
  showProgress: boolean;
}

export function turnstilePresentation(mode: TurnstileWidgetMode): TurnstilePresentation {
  switch (mode) {
    case 'managed':
      return { appearance: 'interaction-only', reserveSpace: false, showProgress: false };
    case 'non-interactive':
      return { appearance: 'always', reserveSpace: true, showProgress: true };
    case 'invisible':
      return { appearance: 'execute', reserveSpace: false, showProgress: false };
  }
}

declare global {
  interface Window {
    turnstile?: TurnstileAPI;
  }
}

const SCRIPT_ID = 'nyauth-turnstile-api';
let loading: Promise<TurnstileAPI> | null = null;

export function loadTurnstile(): Promise<TurnstileAPI> {
  if (typeof window === 'undefined') return Promise.reject(new Error('人机验证只能在浏览器中运行'));
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (loading) return loading;

  loading = new Promise<TurnstileAPI>((resolve, reject) => {
    const existing = document.getElementById(SCRIPT_ID) as HTMLScriptElement | null;
    const script = existing ?? document.createElement('script');
    const finish = () => {
      if (window.turnstile) resolve(window.turnstile);
      else reject(new Error('Cloudflare Turnstile 未能初始化'));
    };
    script.addEventListener('load', finish, { once: true });
    script.addEventListener('error', () => reject(new Error('无法加载 Cloudflare Turnstile')), { once: true });
    if (!existing) {
      script.id = SCRIPT_ID;
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.async = true;
      script.defer = true;
      script.referrerPolicy = 'no-referrer';
      document.head.appendChild(script);
    }
  }).catch((cause) => {
    loading = null;
    throw cause;
  });
  return loading;
}
