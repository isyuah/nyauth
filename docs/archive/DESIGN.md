> [!NOTE]
> **已归档（2026-07-26）**：本规范描述的视觉目标已在 0.3.0 的 Web UI 中基本实现（品牌侧栏、统计卡、登录趋势等），存档仅作设计令牌与尺寸的历史参考。当前 UI 以代码和视觉回归基线（`web/tests/e2e/__screenshots__/`）为准。

# Nya 管理端视觉实现规范（无参考图严格版）

> 版本：3.0（AI 无法读取参考图时使用）  
> 适用对象：AI 编程代理、前端开发者、代码审查者  
> 目标：仅依靠本文档，实现具有固定布局比例、舒展视觉密度、鲜明 Nya 品牌气质和统一组件语言的管理界面，而不是只实现一个“功能相似的普通后台”。

---

# 0. 最高优先级：视觉实现合同

本章优先级高于本文档其他所有章节。出现冲突时，以本章为准。

## 0.1 本文档是唯一视觉真值

实现 AI **无法读取任何参考图**。因此，不得依赖图片理解布局，也不得要求用户再次提供图片。本文档已经把目标界面转换为可执行的尺寸、结构、颜色和组件合同。

AI 必须把以下文件视为最高优先级约束：

```text
DESIGN.md
项目现有前端源码
package.json / 锁文件 / 构建配置
```

优先级从高到低：

```text
1. DESIGN.md 中标记为 MUST / MUST NOT 的条目
2. 本文档中的固定尺寸、Dashboard 蓝图和设计令牌
3. 项目现有业务逻辑、路由和 API 接口
4. 当前组件库的默认外观
```

当现有 UI 与本文档冲突时，应**保留业务逻辑，重做视觉层**。不得因为当前页面已经能运行，就保留与规范明显不一致的布局。

目标不是“理解设计意图后自由发挥”，而是按本文档给出的数值和结构落实。

## 0.2 实现目标不是普通后台

以下结果均视为不合格：

- 仅有白底、细边框、无圆角的传统后台；
- 只有一个小 Logo，没有 `Nya` 字标和品牌插画；
- 字号整体偏小，像浏览器缩放到 80%；
- 卡片被拉得很扁，页面下方出现大片无意义空白；
- 数据为 0 时直接留下空白图表区域；
- 所有内容挤在页面顶部，缺少视觉节奏；
- 只满足“左侧导航 + 顶栏 + 卡片”的结构，但配色、圆角、阴影、角色和密度仍是普通后台；
- 使用默认组件库样式而没有进行主题覆盖。

## 0.3 强制实施顺序

本次任务是修改已有项目，不是从零生成静态样例。AI 必须按以下顺序工作：

1. 读取 `@DESIGN.md`、`@package.json`、构建配置和 `@src` 中与布局有关的文件；
2. 找出 App Shell、Sidebar、Topbar、Dashboard、全局样式、主题 Token 和路由入口；
3. 简要列出准备修改的文件及其职责；
4. 保留已有 API、状态管理、路由、权限判断和事件处理，不随意改后端协议；
5. 先重构 App Shell：Sidebar、Topbar、内容容器；
6. 再重构 Dashboard 标题区和五张统计卡；
7. 再实现登录趋势、最近登录和 Nya 提示卡；
8. 增加仅开发环境生效的 Demo Data 回退，避免全 0 无法验收；
9. 清理已被新布局替代的旧 CSS，避免新旧样式叠加；
10. 运行项目的 lint、typecheck、test、build 中实际存在的命令；
11. 按第 16 章逐项自检，不满足则继续修改；
12. Dashboard 达标后，才复用组件修改用户、应用和身份提供者页面。

禁止一次性重写整个项目、替换框架、删除现有功能，或只创建一个与真实路由无关的演示页面。

## 0.4 标准验收视口

主要验收视口：

```text
宽度：1536px
高度：1024px
设备像素比：1
浏览器缩放：100%
```

辅助验收视口：

```text
1440 × 900
1920 × 1080
1280 × 800
```

禁止通过以下方式“适配”大屏：

```css
zoom: 0.8;
transform: scale(...);
html { font-size: 12px; }
```

必须保持：

```css
html { font-size: 16px; }
body { min-width: 1024px; }
```

## 0.5 Dashboard 固定尺寸合同

在 1536px 宽视口下，允许误差如下：

| 区域 | 目标值 | 允许误差 |
|---|---:|---:|
| Sidebar 宽度 | 248px | ±8px |
| Topbar 高度 | 64px | ±4px |
| Sidebar 品牌区高度 | 168px | ±12px |
| 主内容左右内边距 | 28px | ±4px |
| 主内容顶部内边距 | 20px | ±4px |
| 页面卡片间距 | 16px | ±2px |
| 导航项高度 | 44px | ±2px |
| 统计卡高度 | 112px | ±8px |
| 第二行主卡高度 | 310px | ±20px |
| 卡片圆角 | 12px | ±2px |
| 页面标题字号 | 24px | 不得低于 22px |
| 统计数字字号 | 28px | 不得低于 24px |
| 正文基础字号 | 14px | 不得低于 13px |

若页面肉眼看起来明显“更小、更稀、更扁”，或者像把浏览器缩放到 80%，即使个别数值处于误差边界，也视为不合格。

## 0.6 Dashboard 固定网格

桌面 Dashboard 必须使用如下结构：

```text
┌──────────────────────────────────────────────────────────────┐
│ Page title + welcome text                                    │
├──────────┬──────────┬──────────┬──────────┬──────────┤
│ Stat 1   │ Stat 2   │ Stat 3   │ Stat 4   │ Stat 5   │
├────────────────────────┬───────────────────────┬────────────┤
│ Login trend            │ Recent logins         │ Nya card   │
│ 5/12 width             │ 5/12 width            │ 2/12 width │
└────────────────────────┴───────────────────────┴────────────┘
```

推荐 CSS：

```css
.dashboard-stats {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 16px;
}

.dashboard-main {
  display: grid;
  grid-template-columns: minmax(0, 5fr) minmax(0, 5fr) minmax(210px, 2fr);
  gap: 16px;
}
```

不得把第二行改成三个等宽卡片。

## 0.7 视觉回归要求

开发阶段至少保存：

```text
artifacts/ui/dashboard-1536x1024.png
artifacts/ui/users-1536x1024.png
artifacts/ui/apps-1536x1024.png
```

AI 每次调整全局样式后必须重新检查：

- Sidebar 是否变窄；
- 字号是否被全局样式压缩；
- 卡片圆角和阴影是否消失；
- 品牌区是否退化成普通 Logo；
- 图表和列表是否因真实数据为空而整体塌陷；
- 页面是否出现超过 30% 的无意义空白区域。

## 0.8 针对当前实现的定向整改要求

当前实现已经具备可运行的基础后台，但视觉上属于“压缩后的通用管理页”。AI 修改时必须逐项纠正：

| 当前问题 | 必须修改为 |
|---|---|
| Sidebar 品牌区只有小型抽象图标 | 168px 高品牌区，显示完整 `Nya` 字标、猫耳/角色占位和淡粉紫装饰 |
| Sidebar 过窄、导航密度过小 | 桌面端固定 248px，导航项高 44px，图标与文字间距 12px |
| 页面标题和正文整体过小 | 页面标题 24px，描述 14px，正文基础字号 14px |
| Dashboard 只有 4 张统计卡 | 改为 5 张：用户、应用、7 日登录、活跃会话、7 日失败登录 |
| 所有数据均为 0 | 开发环境启用非零 Demo Data；生产环境仍使用真实 API |
| 第二行是 OIDC 配置、状态文本、快捷操作 | Dashboard 主区域改为 5:5:2：登录趋势、最近登录、Nya 提示卡 |
| OIDC 配置占据 Dashboard 主视觉 | 移到“系统设置 / OIDC 配置”页面，或作为 Dashboard 下方次级信息，不得替代主区域 |
| 卡片是直角/小圆角、细灰边框 | 12px 圆角、柔和边框、极轻阴影、20px 内边距 |
| 内容全部挤在页面顶部 | 统计卡高约 112px，主内容卡高约 310px，保持 16px 网格间距 |
| 页面大面积空白且缺少视觉锚点 | 扩大主卡高度、补齐图表与列表内容、保留右侧品牌提示卡 |
| 激活导航只靠浅色条或细线 | 使用完整淡紫圆角背景，文字与图标使用主色 |
| 顶栏缺少层级 | 固定 64px，高度内对齐折叠、主题、通知和用户头像 |

当前代码中可复用的内容包括：真实统计 API、Issuer/Discovery/JWKS 数据、路由、权限和复制操作。它们可以保留，但展示位置必须服从本规范。

## 0.9 Desktop 页面文字线框

AI 必须按此结构实现，不能自行换成另一种 Dashboard：

```text
┌──────── Sidebar 248 ────────┬──────────────────────── Main ─────────────────────────┐
│ Brand area 168              │ Topbar 64                                             │
│  Nya wordmark               ├────────────────────────────────────────────────────────┤
│  cat/mascot placeholder     │ 仪表盘                                                 │
│                             │ 欢迎回来，Nya Admin！今天也要元气满满喵～              │
│ [仪表盘 active]             │                                                        │
│ 用户管理                    │ [用户] [应用] [7日登录] [活跃会话] [失败登录]          │
│ 应用管理                    │                                                        │
│ 身份提供者                  │ [ 登录趋势 5/12      ][ 最近登录 5/12 ][ Nya 2/12 ]   │
│ 权限管理                    │ [ 7 points + area    ][ 5 login rows  ][ mascot     ]   │
│ 客户端                      │ [                    ][               ][ status text]   │
│ 审计日志                    │                                                        │
│ 系统设置                    │ 可选次级区域：最近事件 / OIDC 端点摘要                 │
│                             │                                                        │
│ [Admin card]                │                                                        │
└─────────────────────────────┴────────────────────────────────────────────────────────┘
```

在内容宽度不足时优先压缩统计卡内部留白，不得先把 Sidebar 和全局字号缩小。


---

# 1. 产品与视觉定位

## 1.1 产品定位

Nya 是供个人、小型团队、自托管服务使用的 OAuth 2.x 与 OpenID Connect 身份系统。

它不是银行后台、ERP、销售中台或大型企业 IAM。视觉应体现：

- 轻量；
- 年轻；
- 可信；
- 对开发者友好；
- 略带 ACG 与猫系品牌感；
- 功能明确，不幼稚，不喧闹。

## 1.2 关键词

```text
Soft / Clean / Youthful / Trustworthy / Developer-friendly / Light ACG
```

## 1.3 ACG 强度

ACG 视觉占整页面积约 10%～15%。

必须出现的位置：

- Sidebar 品牌区：Nya 字标 + 小型角色或猫系插画；
- Dashboard 右侧 Nya 提示卡。

可出现的位置：

- 空状态；
- 登录页；
- 首次配置向导；
- About 页面。

禁止出现的位置：

- Client Secret 展示区；
- 删除确认；
- 高风险安全告警；
- 审计日志高密度表格内部；
- 每一张普通卡片。

---

# 2. 品牌资产

## 2.1 产品名

产品标准名称：

```text
Nya
```

副标题可使用：

```text
身份与授权中心
Nya Identity
OAuth 2.x + OpenID Connect
```

不得把产品名替换为缩写字母或抽象 `M` 图标。

## 2.2 Sidebar 品牌区

品牌区必须具有明确视觉存在感，不得只放一个 16px 图标。

结构：

```text
Nya 字标
小型角色插画 / 猫耳插画
可选淡化猫爪、星光装饰
```

尺寸：

```css
.brand-area {
  height: 168px;
  padding: 22px 20px 14px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}

.brand-wordmark {
  font-size: 36px;
  line-height: 1;
  font-weight: 750;
}

.brand-mascot {
  width: 112px;
  max-height: 86px;
  object-fit: contain;
}
```

背景：极淡粉紫渐变，不允许纯白无装饰。

## 2.3 吉祥物缺失时的处理

没有正式插画资产时，不得：

- 完全删除角色区域；
- 使用随机 Emoji 替代；
- 使用普通用户头像替代；
- 用巨大空白占位。

应使用明确占位组件：

```text
NyaMascotPlaceholder
```

占位应包含柔和猫耳轮廓、星光或猫爪纹理，并保持本规范要求的 112px × 86px 左右视觉面积。

允许完全不依赖图片资产，直接用本地 SVG 或 CSS 绘制一个原创、简化的猫系占位：

- 线条颜色：`#8b6cff`，透明度 0.55～0.8；
- 两个猫耳轮廓；
- 圆形或半圆形头部；
- 两个点状眼睛和极简嘴型；
- 周围最多 3 个星点或猫爪；
- 不得引用现有动漫角色，不得从网络下载随机立绘；
- 必须做成可替换组件，未来可用正式吉祥物资源替换。


---

# 3. 设计令牌

## 3.1 Light Theme

```css
:root {
  color-scheme: light;

  --nya-primary: #7c5cff;
  --nya-primary-hover: #6d4cf5;
  --nya-primary-active: #5f41e6;
  --nya-primary-soft: #f1edff;
  --nya-primary-softer: #f8f5ff;
  --nya-primary-border: #dcd2ff;

  --nya-pink: #f56fa7;
  --nya-pink-soft: #fff0f6;
  --nya-blue: #40a9f3;
  --nya-blue-soft: #edf8ff;
  --nya-mint: #19c79a;
  --nya-mint-soft: #eafbf6;
  --nya-orange: #ff9657;
  --nya-orange-soft: #fff3e9;

  --nya-success: #18b77a;
  --nya-success-soft: #ebfaf3;
  --nya-warning: #ed8b2d;
  --nya-warning-soft: #fff5e9;
  --nya-danger: #ec4b6f;
  --nya-danger-soft: #fff0f3;
  --nya-info: #348ff0;
  --nya-info-soft: #edf6ff;

  --nya-bg: #faf9ff;
  --nya-bg-sidebar: #fffaff;
  --nya-surface: #ffffff;
  --nya-surface-subtle: #fbfaff;
  --nya-surface-muted: #f6f4fb;

  --nya-text-primary: #202235;
  --nya-text-secondary: #62677f;
  --nya-text-tertiary: #9398ac;
  --nya-text-disabled: #b9bdcb;

  --nya-border: #e9e6f1;
  --nya-border-strong: #ddd8e9;
  --nya-divider: #eeebf4;

  --nya-shadow-card: 0 5px 18px rgba(80, 61, 130, 0.055);
  --nya-shadow-hover: 0 9px 26px rgba(80, 61, 130, 0.09);
  --nya-shadow-popup: 0 18px 50px rgba(62, 48, 98, 0.15);

  --nya-radius-sm: 8px;
  --nya-radius-md: 10px;
  --nya-radius-card: 12px;
  --nya-radius-lg: 16px;
  --nya-radius-pill: 999px;
}
```

## 3.2 禁止回退为组件库默认主题

若使用 Ant Design、Element Plus、MUI、Naive UI、Arco、shadcn/ui，必须覆盖：

- primary color；
- border color；
- radius；
- font size；
- card shadow；
- table header；
- menu selected state；
- button height；
- input height；
- focus ring。

“直接使用默认主题，只修改主色”视为不合格。

---

# 4. 排版

## 4.1 字体

```css
font-family:
  Inter,
  "SF Pro Display",
  "SF Pro Text",
  "PingFang SC",
  "Microsoft YaHei",
  system-ui,
  sans-serif;
```

技术字段：

```css
font-family:
  "JetBrains Mono",
  "SFMono-Regular",
  Consolas,
  monospace;
```

## 4.2 字号表

| 用途 | 字号 | 行高 | 字重 |
|---|---:|---:|---:|
| 页面标题 | 24px | 32px | 700 |
| 大卡标题 | 16px | 24px | 650 |
| 统计数字 | 28px | 34px | 720 |
| 导航文字 | 14px | 20px | 520 |
| 正文 | 14px | 21px | 400 |
| 辅助文字 | 13px | 19px | 400 |
| 表格正文 | 13px | 20px | 400 |
| Badge | 12px | 18px | 550 |
| 微型说明 | 12px | 18px | 400 |

禁止：

- 页面主体使用 11px；
- 导航使用 12px 且行高不足；
- 统计数字低于 24px；
- 通过整体缩小字体塞入更多内容。

## 4.3 页面标题区

```css
.page-title {
  margin: 0;
  font-size: 24px;
  line-height: 32px;
  font-weight: 700;
  color: var(--nya-text-primary);
}

.page-description {
  margin-top: 4px;
  font-size: 14px;
  line-height: 21px;
  color: var(--nya-text-secondary);
}
```

Dashboard 标题示例：

```text
仪表盘
欢迎回来，Nya Admin！今天也要元气满满喵～
```

---

# 5. App Shell

## 5.1 根布局

```css
.nya-app {
  min-height: 100vh;
  background: var(--nya-bg);
  color: var(--nya-text-primary);
}

.nya-sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  width: 248px;
  background: var(--nya-bg-sidebar);
  border-right: 1px solid var(--nya-border);
  z-index: 30;
}

.nya-main {
  min-height: 100vh;
  margin-left: 248px;
}

.nya-topbar {
  position: sticky;
  top: 0;
  height: 64px;
  background: rgba(255, 255, 255, 0.94);
  border-bottom: 1px solid var(--nya-divider);
  backdrop-filter: blur(10px);
  z-index: 20;
}

.nya-content {
  padding: 20px 28px 32px;
}
```

不得将 Sidebar 设置为 160px～190px 的窄栏。

## 5.2 Topbar

Topbar 左侧：

- Sidebar 折叠按钮，36px；
- 可选命令面板入口。

Topbar 右侧：

- 主题切换；
- 通知；
- 当前用户头像。

头像应使用 32px 圆形头像或角色头像。只有在无图片时才使用字母占位。

图标按钮：

```css
width: 36px;
height: 36px;
border-radius: 10px;
```

## 5.3 Sidebar 导航

```css
.sidebar-nav {
  padding: 8px 12px;
}

.sidebar-item {
  height: 44px;
  padding: 0 14px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 14px;
}

.sidebar-item[data-active="true"] {
  color: var(--nya-primary);
  background: var(--nya-primary-soft);
  font-weight: 600;
}
```

激活项不能只显示一条左边线。

## 5.4 管理员卡片

Sidebar 底部必须有管理员卡片：

- 头像 34px；
- 主文本：Nya Admin；
- 次文本：超级管理员；
- 右侧展开图标；
- 背景为白色或淡紫；
- 卡片高度约 60px；
- 距离 Sidebar 边缘 12px。

---

# 6. 卡片语言

## 6.1 基础卡片

```css
.nya-card {
  background: var(--nya-surface);
  border: 1px solid var(--nya-border);
  border-radius: var(--nya-radius-card);
  box-shadow: var(--nya-shadow-card);
}
```

基础卡片必须同时具备：

- 轻边框；
- 12px 左右圆角；
- 极轻阴影；
- 足够内边距。

不得使用完全直角、无阴影、强灰边框的表格框风格。

## 6.2 统计卡

结构：

```text
[柔和彩色图标底]  标签
                   数字
                   趋势 + 对比周期
```

建议尺寸：

```css
.stat-card {
  min-height: 112px;
  padding: 20px;
  display: grid;
  grid-template-columns: 48px 1fr;
  column-gap: 14px;
  align-items: center;
}

.stat-icon {
  width: 46px;
  height: 46px;
  border-radius: 50%;
}
```

五张统计卡的图标底色依次可使用：

1. 淡紫；
2. 淡蓝；
3. 淡薄荷绿；
4. 淡橙；
5. 淡粉红。

## 6.3 主内容卡

趋势图、最近登录和提示卡的高度应接近一致。

```css
.dashboard-panel {
  min-height: 310px;
  padding: 20px;
}
```

标题区与内容区间距至少 16px。

---

# 7. Dashboard 详细蓝图

## 7.1 页面头部

垂直结构：

```text
页面标题
4px 间距
欢迎语
20px 间距
统计卡
16px 间距
主内容卡
```

禁止标题区高度不足 45px。

## 7.2 统计卡数据

设计验收模式使用以下模拟数据：

```ts
const dashboardDemo = {
  userCount: 1248,
  appCount: 32,
  loginCount7d: 3862,
  activeSessions: 256,
  failedLogins7d: 23,
};
```

开发环境应支持：

```text
VITE_NYA_DEMO_DATA=true
```

设计评审截图必须启用 Demo Data，避免全部为 0 导致无法检查视觉效果。

生产环境必须使用真实数据。

## 7.3 登录趋势卡

必须包含：

- 标题“登录趋势”；
- 周期“7 天”；
- 时间范围选择；
- 7 个数据点；
- 柔和紫色折线；
- 轻淡面积渐变；
- Hover Tooltip；
- 浅色网格线。

不得：

- 留下空白大框；
- 使用纯黑坐标轴；
- 使用超过两条主曲线；
- 使用高饱和渐变背景。

图表无数据时应显示小型空状态，不允许整个卡片内容消失。

## 7.4 最近登录卡

默认显示 5 条：

- 头像；
- 用户名；
- 角色 Badge；
- 登录结果；
- IP；
- 相对时间。

行高约 48px～52px。

卡片右上角显示“查看全部”。

失败登录使用红色状态文字，但整行不铺红色背景。

## 7.5 Nya 提示卡

该卡是 Dashboard 的品牌锚点，必须保留。

布局：

```text
上半部分：角色插画，占卡片约 55%～65% 高度
下半部分：提示标题 + 两行状态文字
背景：极淡粉紫
装饰：少量猫爪或星光
```

示例：

```text
Nya 提示
系统运行良好！
所有服务正常，最近未发现异常登录。
```

提示卡宽度不得小于 200px。

角色不得缩成 32px 头像。

## 7.6 系统无数据状态

若系统刚安装、用户和应用均为 0：

- 统计卡仍保留完整高度；
- 数值可以为 0；
- 趋势卡显示空状态插画和“暂无登录数据”；
- 最近登录显示“尚无登录记录”；
- Nya 提示卡引导“创建第一个用户或应用”；
- 不允许页面主体大面积空白。

---

# 8. Button、Input、Badge

## 8.1 Button

高度：

```text
Small: 32px
Default: 38px
Large: 44px
```

默认圆角 9px～10px。

Primary：

```css
background: var(--nya-primary);
color: #fff;
box-shadow: 0 5px 12px rgba(124, 92, 255, 0.20);
```

每个页面最多一个主要 Primary Action。

## 8.2 Input

```css
height: 38px;
border: 1px solid var(--nya-border-strong);
border-radius: 9px;
background: #fff;
font-size: 14px;
```

Focus：

```css
border-color: var(--nya-primary);
box-shadow: 0 0 0 3px rgba(124, 92, 255, 0.13);
```

## 8.3 Badge

Badge 应使用低饱和浅底色。

禁止一个表格单行出现超过 3 个彩色 Badge。

---

# 9. 表格与数据页

## 9.1 表格卡

表格必须位于圆角卡片中，而不是直接在页面上绘制大量网格线。

表头：

```css
height: 44px;
background: var(--nya-surface-subtle);
color: var(--nya-text-secondary);
font-size: 12px;
font-weight: 600;
```

表格行：

```css
min-height: 52px;
border-bottom: 1px solid var(--nya-divider);
```

禁止每个单元格都有边框。

## 9.2 用户管理页

结构：

```text
Page Header                     [创建用户]
统计摘要或说明卡（可选）
搜索 + 状态筛选 + 来源筛选
用户表格
分页
用户详情 Drawer
```

## 9.3 应用管理页

结构：

```text
Page Header                     [创建应用]
应用搜索与类型筛选
左侧应用列表 / 表格
右侧应用详情或独立详情页
```

详情至少包含：

- Client ID；
- Client Secret；
- Redirect URI；
- Grant Type；
- Scope；
- PKCE；
- Token 生命周期；
- 状态；
- 危险区域。

## 9.4 身份提供者页

支持：

- Nya Local；
- GitHub；
- Google；
- 通用 OIDC；
- 其他项目实际支持的来源。

每项显示 Logo、名称、类型、状态和编辑操作。

---

# 10. OAuth / OIDC 安全交互

## 10.1 Client Secret

默认遮挡。

显示 Secret 必须是主动操作。

重新生成时必须提示：

```text
重新生成后，旧 Client Secret 将立即失效。使用旧 Secret 的应用将无法继续认证。
```

## 10.2 Redirect URI

每条 URI 单独一行，支持：

- 添加；
- 删除；
- 复制；
- 校验；
- 本地开发地址说明。

生产应用出现 `http://` 非 localhost 地址时显示警告。

## 10.3 技术字段

以下内容使用等宽字体：

- Client ID；
- Client Secret；
- Issuer；
- Discovery Endpoint；
- JWKS Endpoint；
- Redirect URI；
- Trace ID；
- Token ID。

技术字段不得使用浅灰小字导致不可读。

---

# 11. 状态、空状态与错误状态

每一个数据组件必须具备：

```text
Loading
Loaded
Empty
Error
```

## 11.1 Loading

使用与真实组件结构一致的 Skeleton。

禁止只在页面中央显示一个微型 Spinner。

## 11.2 Empty

空状态应包含：

- 小型 Nya 插画或标准线性图标；
- 明确说明；
- 可执行动作。

示例：

```text
还没有应用
创建第一个 OAuth / OIDC 客户端后，它会显示在这里。
[创建应用]
```

## 11.3 Error

必须展示：

- 发生了什么；
- 用户可以做什么；
- 重试按钮；
- 可选错误编号。

---

# 12. 动效

时长：

```text
Hover: 120ms～160ms
普通切换: 180ms～220ms
Drawer / Modal: 220ms～280ms
```

允许：

- 颜色和阴影平滑变化；
- Drawer 淡入滑动；
- 图表载入动画；
- Toast 淡入。

禁止：

- 卡片 Hover 明显上跳；
- 弹簧式夸张动画；
- 猫耳持续抖动；
- 大面积背景持续流动；
- 功能界面中的粒子特效。

---

# 13. 响应式

## 13.1 ≥ 1280px

- Sidebar 248px；
- Dashboard 五列统计卡；
- 第二行 5:5:2；
- 主内容填满可用宽度。

## 13.2 1024px～1279px

- Sidebar 可折叠为 72px；
- 统计卡为 3 + 2；
- Dashboard 第二行可变为 2 列，Nya 卡进入下一行；
- 字号不缩小。

## 13.3 768px～1023px

- Sidebar 使用 Drawer；
- 统计卡两列；
- 其他内容单列；
- 表格允许列裁剪，不默认全页面横向滚动。

## 13.4 < 768px

管理端仅保证核心查看和简单操作。

不得通过整体缩放桌面页面实现手机适配。

---

# 14. 组件目录建议

```text
src/
  components/
    layout/
      NyaAppShell.tsx
      NyaSidebar.tsx
      NyaTopbar.tsx
      NyaPageHeader.tsx
    brand/
      NyaWordmark.tsx
      NyaMascot.tsx
      NyaMascotPlaceholder.tsx
      NyaTipCard.tsx
    ui/
      NyaButton.tsx
      NyaCard.tsx
      NyaInput.tsx
      NyaBadge.tsx
      NyaAvatar.tsx
      NyaEmpty.tsx
      NyaError.tsx
      NyaSkeleton.tsx
    dashboard/
      DashboardStatCard.tsx
      LoginTrendCard.tsx
      RecentLoginCard.tsx
    oauth/
      ClientSecretField.tsx
      RedirectUriEditor.tsx
      ScopeSelector.tsx
      GrantTypeSelector.tsx
  styles/
    tokens.css
    global.css
    components.css
  assets/
    nya/
      wordmark.svg
      mascot-dashboard.webp
      mascot-empty.webp
      paw-pattern.svg
```

不得在各页面复制粘贴一套略有差异的 Card、Button、Badge。

---

# 15. AI 开发强制规则

## 15.1 MUST

AI 必须：

1. 读取 `@DESIGN.md` 和项目现有前端源码；
2. 先实现 App Shell，再实现 Dashboard；
3. 使用本规范中的固定尺寸，不自行缩小；
4. 保持 `html` 字号 16px；
5. 保持 Sidebar 248px；
6. 保持 Topbar 64px；
7. Dashboard 使用五张统计卡；
8. Dashboard 第二行使用 5:5:2 网格；
9. Sidebar 显示 Nya 字标与品牌插画；
10. Dashboard 显示 Nya 提示卡；
11. Card 使用 12px 圆角、轻边框和轻阴影；
12. 设计评审时使用非零 Demo Data；
13. 所有数据组件实现 Loading、Empty、Error；
14. OAuth / OIDC 技术字段使用等宽字体和复制操作；
15. 对危险操作提供确认；
16. 每次全局样式调整后在浏览器实际检查布局；
17. 完成页面前逐项执行验收清单。

## 15.2 MUST NOT

AI 不得：

1. 用普通字母 Logo 替代 Nya 品牌区；
2. 删除 Sidebar 品牌插画区；
3. 删除 Dashboard 提示卡；
4. 使用默认组件库风格交付；
5. 将 Sidebar 缩到 200px 以下；
6. 将 Topbar 缩到 52px 以下；
7. 将正文整体缩到 12px；
8. 使用 `zoom`、`scale` 或修改根字号适配大屏；
9. 使用直角平面卡片替代圆角软卡片；
10. 因后端返回 0 而让 Dashboard 主内容塌陷；
11. 在页面底部留下大片无意义空白；
12. 用一组空边框框出所有内容；
13. 使用蓝灰企业后台默认配色；
14. 使用高饱和霓虹或大面积玻璃拟态；
15. 将所有 ACG 元素删除，声称是为了“专业”；
16. 在安全危险操作中使用卖萌文案；
17. 把 OpenID Connect 写成 OpenConnect；
18. 在未运行和未进行尺寸自检的情况下宣称页面已还原。

## 15.3 AI 输出代码前的说明

AI 在提交 UI 实现时必须说明：

```text
- 使用的参考视口
- App Shell 的实际尺寸
- Dashboard 网格结构
- Demo Data 开关
- 已实现的状态
- 仍缺失的插画资产
```

不得只说“已优化 UI”“已按要求实现”。

---

# 16. Dashboard 验收清单

## 16.1 结构

- [ ] Sidebar 宽度为 240px～256px；
- [ ] Topbar 高度为 60px～68px；
- [ ] 主内容左右内边距为 24px～32px；
- [ ] 页面标题不小于 22px；
- [ ] 第一行正好五张统计卡；
- [ ] 第二行是趋势图、最近登录、Nya 提示卡；
- [ ] 第二行宽度接近 5:5:2；
- [ ] 页面没有因数据为空出现大片空白。

## 16.2 品牌

- [ ] 显示完整 `Nya` 字标；
- [ ] Sidebar 品牌区有插画或合格占位；
- [ ] Dashboard 有 Nya 提示卡；
- [ ] 粉紫装饰克制但可见；
- [ ] 页面一眼能识别为 Nya，而非通用后台。

## 16.3 视觉

- [ ] 卡片圆角约 12px；
- [ ] 卡片有轻边框和轻阴影；
- [ ] 统计图标为彩色柔和圆形底；
- [ ] 正文没有小于 12px 的关键内容；
- [ ] 统计数字不小于 24px；
- [ ] 图表网格线和坐标轴足够柔和；
- [ ] 颜色符合 Token；
- [ ] 没有默认组件库蓝色残留。

## 16.4 内容

- [ ] 设计评审模式不是全 0 数据；
- [ ] 趋势图至少有 7 个数据点；
- [ ] 最近登录至少有 5 条示例数据；
- [ ] 登录成功和失败状态可区分；
- [ ] 无数据时显示明确空状态。

---

# 17. 其他页面验收

## 17.1 用户管理

- [ ] 页面标题与创建用户按钮层级清晰；
- [ ] 搜索和筛选位于表格卡顶部；
- [ ] 用户名为主信息，邮箱为次信息；
- [ ] 状态和角色 Badge 克制；
- [ ] 表格没有密集单元格边框；
- [ ] 详情使用 Drawer 或独立页；
- [ ] 空状态不是空白表格。

## 17.2 应用管理

- [ ] Client ID 可复制；
- [ ] Secret 默认遮挡；
- [ ] Redirect URI 可编辑和校验；
- [ ] Scope、Grant Type、PKCE 分组清晰；
- [ ] 删除和重新生成 Secret 有确认；
- [ ] 页面仍保持 Nya 视觉语言。

## 17.3 身份提供者

- [ ] IdP Logo 和名称可辨识；
- [ ] 支持测试连接；
- [ ] 状态明确；
- [ ] Secret 不泄露；
- [ ] 配置表单分组清晰。

---

# 18. AI 修改现有项目的使用方式

完整执行提示词已经单独提供在：

```text
AI_REFACTOR_PROMPT.md
```

调用 AI 编程代理时，至少 @ 提及：

```text
@DESIGN.md
@package.json
@src
```

若编辑器不能 @ 整个目录，则改为 @ 提及以下实际文件：

```text
应用入口文件
路由文件
AppLayout / MainLayout
Sidebar
Topbar / Header
Dashboard 页面
全局 CSS / Tailwind 配置 / Theme 文件
Dashboard API 或 Store
```

不要只发送一句“按 DESIGN.md 优化”。应使用 `AI_REFACTOR_PROMPT.md` 中的完整提示词，它包含现状诊断、修改边界、实施顺序和完成条件。

---

# 19. 最终目标

Nya 管理端应当让用户第一眼感受到：

```text
这是一个清爽、可信、年轻、带一点猫系 ACG 气质的身份系统，
而不是换了紫色主题的通用企业后台。
```

功能正确只是最低要求；布局比例、视觉密度和品牌识别度同样属于完成标准。
