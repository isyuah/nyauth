const root = document.querySelector('#preview-root');
const stateSelect = document.querySelector('#state-select');
const schemeButtons = Array.from(document.querySelectorAll('[data-scheme]'));
const siteLogo = '../../../web/static/logo.png';

let scheme = new URLSearchParams(window.location.search).get('scheme') === 'complete' ? 'complete' : 'focused';
let state = new URLSearchParams(window.location.search).get('state') || 'consent-mixed';
let actionsObserver;
let quickActionsElement;
let originalActionsRatio = 1;
const quickActionsMedia = window.matchMedia('(max-height: 820px), (max-width: 760px)');

const icon = (name, className = '') => {
  const nodes = {
    'check': '<path d="m5 12 4 4L19 6"></path>',
    'circle-check': '<circle cx="12" cy="12" r="9"></circle><path d="m8.5 12 2.25 2.25L15.5 9.5"></path>',
    'circle-check-big': '<path d="M21.801 10A10 10 0 1 1 17 3.335"></path><path d="m9 11 3 3L22 4"></path>',
    'circle-info': '<circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path>',
    'circle-x': '<circle cx="12" cy="12" r="10"></circle><path d="m15 9-6 6"></path><path d="m9 9 6 6"></path>',
    'x': '<path d="M18 6 6 18"></path><path d="m6 6 12 12"></path>',
  };
  return `<svg class="lucide-icon ${className}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${nodes[name]}</svg>`;
};

const brandLine = (secureText = '') => `
  <div class="brand-line">
    <div class="brand-identity">
      <img src="${siteLogo}" alt="Nyauth Logo">
      <span><strong>Nyauth</strong><small>身份与访问中心</small></span>
    </div>
    ${secureText ? `<span class="secure-label">${secureText}</span>` : ''}
  </div>`;

const accountRow = `
  <div class="account-row">
    <span class="avatar" aria-hidden="true">Y</span>
    <span class="account-copy"><span>以此账户继续</span><strong>Yu</strong></span>
    <span class="account-email">yu@example.com</span>
  </div>`;

const technicalDetails = (deviceFlow = true) => `
  <div class="tech-details">
    <button class="tech-summary" type="button" aria-expanded="false">${icon('circle-info')}<span>应用技术信息</span></button>
    <div class="tech-details-popover" aria-hidden="true">
      <dl class="tech-grid">
        <dt>Client ID</dt><dd class="mono">igMJZ6IoZT0MShoDbhRvTQ</dd>
        <dt>注册来源</dt><dd>系统管理员配置</dd>
        <dt>发布者状态</dt><dd>已由管理员审核</dd>
        <dt>${deviceFlow ? '授权方式' : '回调来源'}</dt><dd>${deviceFlow ? '设备代码授权，不会跳转至第三方回调地址' : '<span class="mono">https://app.example.com</span>'}</dd>
      </dl>
      <nav class="app-links" aria-label="应用信息链接"><a href="#homepage">应用主页 ↗</a><a href="#privacy">隐私政策</a><a href="#terms">服务条款</a></nav>
    </div>
  </div>`;

const permissionTile = ({ optional = false, sensitive = false, name, scope, risk, description, claims, history }) => {
  const body = `
    ${optional
      ? `<input class="permission-checkbox-input" type="checkbox" checked aria-label="允许${name}"><span class="custom-checkbox" aria-hidden="true">${icon('check', 'selection-check')}${icon('x', 'selection-x')}</span>`
      : `<span class="permission-required" aria-label="必需权限">${icon('circle-check')}</span>`}
    <span class="permission-main">
      <span class="permission-top">
        <span class="permission-name">${name}</span>
        <code class="scope-name mono">${scope}</code>
        <span class="risk-chip ${sensitive ? 'high' : risk === '个人数据' ? 'personal' : 'low'}">${sensitive ? '敏感权限' : risk}</span>
        ${history ? `<span class="history-chip ${history === '新增请求' ? 'new' : ''}">${history}</span>` : ''}
      </span>
      <p>${description}</p>
      ${claims ? `<span class="claims">包含：${claims}</span>` : ''}
    </span>`;
  return optional
    ? `<label class="permission-tile ${sensitive ? 'sensitive' : ''}">${body}</label>`
    : `<div class="permission-tile ${sensitive ? 'sensitive' : ''}">${body}</div>`;
};

const permissionSections = (variant, mixed) => {
  const required = [
    { name: '确认身份', scope: 'openid', risk: '低风险', description: '使用稳定账户标识完成 OpenID Connect 登录。', claims: '稳定用户 ID', history: '之前已授权' },
    { name: '基本资料', scope: 'profile', risk: '个人数据', description: '读取用户名、显示名称和头像。', claims: '用户名、显示名称、头像', history: '之前已授权' },
    { name: '邮箱信息', scope: 'email', risk: '个人数据', description: '读取邮箱地址及邮箱验证状态。', claims: '邮箱地址、邮箱验证状态', history: '之前已授权' },
    { name: '管理项目', scope: 'projects.write', sensitive: true, description: '创建、修改和归档您有权管理的项目。', claims: '', history: '新增请求' },
  ];
  const optional = [
    { optional: true, name: '离线访问', scope: 'offline_access', sensitive: true, description: '允许应用在您离开后继续使用可轮换的 Refresh Token。', history: '新增请求' },
    { optional: true, name: '读取审计摘要', scope: 'audit.summary', risk: '个人数据', description: '读取与此应用有关的低敏感度操作摘要。', history: '' },
  ];
  return `
    <section class="permission-section" aria-labelledby="required-title">
      <div class="section-heading"><h2 id="required-title">必需权限</h2><span>不同意时只能拒绝整个请求</span></div>
      <div class="permission-stack">${required.map(permissionTile).join('')}</div>
    </section>
    ${mixed ? `<section class="permission-section" aria-labelledby="optional-title">
      <div class="section-heading"><h2 id="optional-title">可选权限</h2></div>
      <div class="permission-stack">${optional.map(permissionTile).join('')}</div>
    </section>` : ''}
    ${variant === 'focused' && mixed ? '<p class="claims">关闭可选权限后，应用收到的 Token Scope 会相应缩减，部分功能可能不可用。</p>' : ''}`;
};

function focusedConsent(mixed) {
  return `<section class="auth-surface focused" aria-label="方案 A 授权确认">
    <div class="surface-pad">
      ${brandLine('设备授权')}
      <div class="client-heading">
        <span class="client-logo" aria-hidden="true">D</span>
        <div class="client-copy"><h1>Device Test</h1><p>请求在另一台设备上访问您的账户</p><div class="client-status"><span class="trust-chip">管理员配置应用</span></div></div>
      </div>
      ${accountRow}
      <div class="notice">此应用由 Nyauth 管理员直接配置和管理。请确认这是您刚刚操作的设备。</div>
      ${technicalDetails(true)}
      ${permissionSections('focused', mixed)}
      <div class="consent-actions"><button class="btn" type="button">拒绝</button><button class="btn primary" type="button">允许设备访问</button></div>
    </div>
  </section>`;
}

function completeConsent(mixed) {
  return `<section class="auth-surface complete" aria-label="方案 B 授权确认">
    <div class="surface-pad">
      ${brandLine()}
      <div class="client-heading">
        <span class="client-logo" aria-hidden="true">D</span>
        <div class="client-copy"><h1>Device Test</h1><p>希望在另一台设备上使用您的 Nyauth 账户</p><div class="client-status"><span class="trust-chip">已验证发布者</span></div></div>
      </div>
      ${accountRow}
      <div class="notice">只在您刚刚主动操作了电视、终端或其他设备时继续。</div>
      ${technicalDetails(true)}
      ${permissionSections('complete', mixed)}
      <div class="consent-actions" data-primary-actions><button class="btn" type="button">拒绝请求</button><button class="btn primary" type="button">允许所选权限</button></div>
    </div>
    <div class="quick-consent-actions" aria-hidden="true" inert><div class="quick-consent-actions-inner"><button class="btn" type="button">拒绝请求</button><button class="btn primary" type="button">允许所选权限</button></div></div>
  </section>`;
}

function focusedCode() {
  return `<section class="auth-surface focused compact" aria-label="方案 A 设备代码输入">
    <div class="surface-pad code-layout">
      ${brandLine('连接设备')}
      <h1>输入设备代码</h1>
      <p class="page-copy">输入电视、终端或其他设备上显示的 8 位代码。</p>
      <label class="field-label" for="focused-code">设备代码</label>
      <input id="focused-code" class="code-input" value="K804-J64X" maxlength="9" autocomplete="one-time-code">
      <p class="field-hint">代码不区分大小写，连字符可以省略。</p>
      <button class="btn primary full" type="button">继续查看授权信息</button>
      <div class="notice safety-note">下一步会显示应用身份和具体权限。只有在您刚刚主动操作该设备时才应继续。</div>
    </div>
  </section>`;
}

function completeCode() {
  return `<section class="auth-surface complete compact" aria-label="方案 B 设备代码输入">
    <div class="complete-code">
      <aside class="code-intro">
        <div class="brand-identity"><img src="${siteLogo}" alt="Nyauth Logo"><span><strong>Nyauth</strong><small>安全设备连接</small></span></div>
        <h1>连接您的设备</h1>
        <p>代码只用于找到设备发起的授权请求，不会直接授予任何权限。</p>
        <ul><li>核对应用身份</li><li>逐项确认请求权限</li><li>可随时拒绝整个请求</li></ul>
      </aside>
      <div class="code-form code-layout">
        <h1>输入设备代码</h1>
        <p class="page-copy">在下方输入电视、终端或其他设备显示的代码。</p>
        <label class="field-label" for="complete-code">设备代码</label>
        <input id="complete-code" class="code-input" value="K804-J64X" maxlength="9" autocomplete="one-time-code">
        <p class="field-hint">支持直接粘贴；字母大小写和连字符不会影响验证。</p>
        <button class="btn primary full" type="button">验证并继续</button>
      </div>
    </div>
  </section>`;
}

function focusedResult(approved) {
  return `<section class="auth-surface focused result-surface" aria-label="方案 A 授权结果">
    <div class="surface-pad">${brandLine('设备授权结果')}</div>
    <div class="result-content" style="padding-top: 0">
      <div class="result-mark ${approved ? '' : 'denied'}">${icon(approved ? 'circle-check-big' : 'circle-x')}</div>
      <h1>${approved ? 'Device Test 已获授权' : '已拒绝 Device Test'}</h1>
      <p>${approved ? '授权信息已经安全发送给发起请求的设备。' : '设备不会获得您的账户 Token 或任何请求权限。'}</p>
      <div class="result-app"><span class="client-logo">D</span><span><strong>Device Test</strong><span>${approved ? '已允许 5 项必需权限和 1 项可选权限' : '本次请求未获得授权'}</span></span></div>
      <div class="next-step">${approved ? '下一步：返回设备继续操作。这个页面现在可以安全关闭。' : '下一步：您可以安全关闭此页面；需要时由设备重新发起请求。'}</div>
    </div>
  </section>`;
}

function completeResult(approved) {
  return `<section class="auth-surface complete result-surface" aria-label="方案 B 授权结果">
    <div class="complete-result">
      <div class="result-summary ${approved ? '' : 'denied'}">
        <div class="result-mark ${approved ? '' : 'denied'}">${icon(approved ? 'circle-check-big' : 'circle-x')}</div>
        <h1>${approved ? '设备已获授权' : '设备访问已拒绝'}</h1>
        <p>${approved ? 'Device Test 可以继续完成登录。' : '本次请求没有获得任何访问权限。'}</p>
      </div>
      <div class="result-detail">
        ${brandLine()}
        <h2>本次操作</h2>
        <div class="result-app"><span class="client-logo">D</span><span><strong>Device Test</strong><span>操作账户：Yu · yu@example.com</span></span></div>
        <div class="next-step">${approved ? '<strong>返回发起请求的设备</strong><br>设备会自动继续；本页面可以安全关闭。' : '<strong>无需进行其他操作</strong><br>可以关闭本页面，设备需要重新发起授权。'}</div>
      </div>
    </div>
  </section>`;
}

function render() {
  const mixed = state === 'consent-mixed';
  if (state === 'code') root.innerHTML = scheme === 'focused' ? focusedCode() : completeCode();
  else if (state === 'approved') root.innerHTML = scheme === 'focused' ? focusedResult(true) : completeResult(true);
  else if (state === 'denied') root.innerHTML = scheme === 'focused' ? focusedResult(false) : completeResult(false);
  else root.innerHTML = scheme === 'focused' ? focusedConsent(mixed) : completeConsent(mixed);

  document.body.dataset.scheme = scheme;
  schemeButtons.forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.scheme === scheme)));
  stateSelect.value = state;
  const params = new URLSearchParams({ scheme, state });
  window.history.replaceState(null, '', `${window.location.pathname}?${params}`);
  observeConsentActions();
}

function observeConsentActions() {
  actionsObserver?.disconnect();
  actionsObserver = undefined;
  quickActionsElement = undefined;
  originalActionsRatio = 1;

  const actions = root.querySelector('[data-primary-actions]');
  const quickActions = root.querySelector('.quick-consent-actions');
  if (!actions || !quickActions) return;
  quickActionsElement = quickActions;

  actionsObserver = new IntersectionObserver(([entry]) => {
    originalActionsRatio = entry.intersectionRatio;
    updateQuickActionsVisibility();
  }, { threshold: [0, 0.85, 1] });
  actionsObserver.observe(actions);
}

function updateQuickActionsVisibility() {
  if (!quickActionsElement) return;
  const visible = quickActionsMedia.matches && originalActionsRatio < 0.85;
  quickActionsElement.classList.toggle('is-visible', visible);
  quickActionsElement.setAttribute('aria-hidden', String(!visible));
  quickActionsElement.inert = !visible;
}

quickActionsMedia.addEventListener('change', updateQuickActionsVisibility);

schemeButtons.forEach((button) => button.addEventListener('click', () => {
  scheme = button.dataset.scheme;
  render();
}));

stateSelect.addEventListener('change', () => {
  state = stateSelect.value;
  render();
});

const setTechnicalDetailsOpen = (details, open) => {
  details.classList.toggle('is-open', open);
  details.querySelector('.tech-summary').setAttribute('aria-expanded', String(open));
  details.querySelector('.tech-details-popover').setAttribute('aria-hidden', String(!open));
};

document.addEventListener('click', (event) => {
  if (!(event.target instanceof Element)) return;
  const trigger = event.target.closest('.tech-summary');
  const details = event.target.closest('.tech-details');

  if (trigger) {
    root.querySelectorAll('.tech-details.is-open').forEach((openDetails) => {
      if (openDetails !== details) setTechnicalDetailsOpen(openDetails, false);
    });
    setTechnicalDetailsOpen(details, !details.classList.contains('is-open'));
    return;
  }

  if (!details) {
    root.querySelectorAll('.tech-details.is-open').forEach((openDetails) => {
      setTechnicalDetailsOpen(openDetails, false);
    });
  }
});

root.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  const details = root.querySelector('.tech-details.is-open');
  if (!details) return;
  setTechnicalDetailsOpen(details, false);
  details.querySelector('.tech-summary').focus();
});

if (![...stateSelect.options].some((option) => option.value === state)) state = 'consent-mixed';
render();
