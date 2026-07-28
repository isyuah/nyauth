<script lang="ts">
  import {
    buildCalendarMonth,
    combineLocalDateTime,
    formatLocalDateTime,
    isWithinDateRange,
    orderedDateRange,
    parseDateKey,
    parseLocalDateTime,
    shiftCalendarMonth,
    splitLocalDateTime,
    type CalendarDay,
  } from '$lib/date-time-range';
  import { CalendarDays, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, X } from 'lucide-svelte';
  import Button from './Button.svelte';
  import Modal from './Modal.svelte';
  import TimePicker from './TimePicker.svelte';

  let {
    id = 'date-time-range',
    label = '时间范围',
    from = $bindable(''),
    to = $bindable(''),
    showSeconds = false,
    onconfirm,
  }: {
    id?: string;
    label?: string;
    from?: string;
    to?: string;
    showSeconds?: boolean;
    onconfirm?: () => void | Promise<void>;
  } = $props();

  const weekdays = ['一', '二', '三', '四', '五', '六', '日'];
  const quickRanges = [1, 7, 14, 30];

  let open = $state(false);
  let visibleYear = $state(new Date().getFullYear());
  let visibleMonth = $state(new Date().getMonth());
  let draftStartDate = $state('');
  let draftEndDate = $state('');
  let draftStartTime = $state('00:00');
  let draftEndTime = $state('23:59');
  let endAtConfirmation = $state(false);
  let selectionPhase = $state<'start' | 'end'>('start');
  let validationError = $state('');

  let calendarDays = $derived(buildCalendarMonth(visibleYear, visibleMonth));
  let monthTitle = $derived(`${visibleYear} 年 ${visibleMonth + 1} 月`);
  let triggerValue = $derived(formatRangeLabel(from, to));
  let selectionHint = $derived(
    endAtConfirmation
      ? (draftStartDate ? '已选择起始日期；结束时间将在确认时确定' : '请选择起始日期')
      : selectionPhase === 'end'
        ? '请选择结束日期'
        : '请选择起始日期',
  );

  function formatDisplayDateTime(value: string): string {
    const parsed = parseLocalDateTime(value);
    if (!parsed) return '';
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
      second: showSeconds ? '2-digit' : undefined,
    }).format(parsed);
  }

  function formatRangeLabel(start: string, end: string): string {
    const startLabel = formatDisplayDateTime(start);
    const endLabel = formatDisplayDateTime(end);
    if (startLabel && endLabel) return `${startLabel} - ${endLabel}`;
    if (startLabel) return `${startLabel} - 未设置结束时间`;
    if (endLabel) return `未设置开始时间 - ${endLabel}`;
    return '选择日期和时间范围';
  }

  function openPicker() {
    const start = splitLocalDateTime(from, showSeconds ? '00:00:00' : '00:00', showSeconds);
    const end = splitLocalDateTime(to, showSeconds ? '23:59:59' : '23:59', showSeconds);
    const focusDate = parseDateKey(start.date) || parseDateKey(end.date) || new Date();
    draftStartDate = start.date;
    draftStartTime = start.time;
    draftEndDate = end.date;
    draftEndTime = end.time;
    endAtConfirmation = false;
    selectionPhase = start.date && !end.date ? 'end' : 'start';
    visibleYear = focusDate.getFullYear();
    visibleMonth = focusDate.getMonth();
    validationError = '';
    open = true;
  }

  function moveMonth(delta: number) {
    const next = shiftCalendarMonth(visibleYear, visibleMonth, delta);
    visibleYear = next.year;
    visibleMonth = next.month;
  }

  function chooseDay(dateKey: string) {
    validationError = '';
    const selectedDate = parseDateKey(dateKey);
    if (selectedDate && (selectedDate.getFullYear() !== visibleYear || selectedDate.getMonth() !== visibleMonth)) {
      visibleYear = selectedDate.getFullYear();
      visibleMonth = selectedDate.getMonth();
    }

    if (endAtConfirmation || selectionPhase === 'start') {
      draftStartDate = dateKey;
      if (!endAtConfirmation) draftEndDate = '';
      selectionPhase = endAtConfirmation ? 'start' : 'end';
      return;
    }

    [draftStartDate, draftEndDate] = orderedDateRange(draftStartDate, dateKey);
    selectionPhase = 'start';
  }

  function setQuickRange(days: number) {
    const end = new Date();
    end.setSeconds(0, 0);
    const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
    const startValue = formatLocalDateTime(start, showSeconds);
    const endValue = formatLocalDateTime(end, showSeconds);
    const startParts = splitLocalDateTime(startValue, showSeconds ? '00:00:00' : '00:00', showSeconds);
    const endParts = splitLocalDateTime(endValue, showSeconds ? '23:59:59' : '23:59', showSeconds);
    draftStartDate = startParts.date;
    draftStartTime = startParts.time;
    draftEndDate = endParts.date;
    draftEndTime = endParts.time;
    endAtConfirmation = false;
    selectionPhase = 'start';
    visibleYear = start.getFullYear();
    visibleMonth = start.getMonth();
    validationError = '';
  }

  function handleEndModeChange() {
    validationError = '';
    selectionPhase = endAtConfirmation ? 'start' : (draftStartDate && !draftEndDate ? 'end' : 'start');
  }

  function dayLabel(day: CalendarDay): string {
    const value = parseDateKey(day.dateKey);
    return value
      ? new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: 'long', day: 'numeric' }).format(value)
      : day.dateKey;
  }

  function dayClass(day: CalendarDay): string {
    const isEndpoint = day.dateKey === draftStartDate || (!endAtConfirmation && day.dateKey === draftEndDate);
    const inRange = !endAtConfirmation && isWithinDateRange(day.dateKey, draftStartDate, draftEndDate);
    return [
      'flex h-9 w-full items-center justify-center rounded-nya-sm text-body transition-colors',
      isEndpoint
        ? 'bg-nya-primary font-semibold text-white'
        : inRange
          ? 'bg-nya-primary-soft text-nya-primary'
          : day.inCurrentMonth
            ? 'text-nya-text-primary hover:bg-nya-surface-muted'
            : 'text-nya-text-disabled hover:bg-nya-surface-muted',
      day.isToday && !isEndpoint ? 'ring-1 ring-inset ring-nya-primary' : '',
    ].join(' ');
  }

  async function confirmRange() {
    validationError = '';
    if (!draftStartDate) {
      validationError = '请选择起始日期。';
      return;
    }
    if (!endAtConfirmation && !draftEndDate) {
      validationError = '请选择结束日期，或启用“结束时间使用确认时刻”。';
      return;
    }

    const startValue = combineLocalDateTime(draftStartDate, draftStartTime);
    const endValue = endAtConfirmation
      ? formatLocalDateTime(new Date(), showSeconds)
      : combineLocalDateTime(draftEndDate, draftEndTime);
    const parsedStart = parseLocalDateTime(startValue);
    const parsedEnd = parseLocalDateTime(endValue);
    if (!parsedStart || !parsedEnd) {
      validationError = '日期或时间无效。';
      return;
    }
    if (parsedEnd.getTime() < parsedStart.getTime()) {
      validationError = '结束时间不能早于起始时间。';
      return;
    }

    from = startValue;
    to = endValue;
    open = false;
    await onconfirm?.();
  }

  async function clearRange() {
    from = '';
    to = '';
    open = false;
    validationError = '';
    await onconfirm?.();
  }
</script>

<div class="flex flex-col gap-1.5">
  <label for={id} class="text-body-medium text-nya-text-primary">{label}</label>
  <div class="flex h-[38px] w-full overflow-hidden rounded-nya-sm border border-nya-border bg-nya-surface text-body text-nya-text-primary transition-all duration-fast hover:border-nya-border-strong focus-within:border-nya-primary focus-within:ring-2 focus-within:ring-nya-primary/24">
    <button
      id={id}
      type="button"
      aria-haspopup="dialog"
      onclick={openPicker}
      class="flex min-w-0 flex-1 items-center justify-between gap-3 px-3 text-left focus:outline-none"
    >
      <span class="min-w-0 truncate" class:text-nya-text-tertiary={!from && !to}>{triggerValue}</span>
      <CalendarDays size={17} class="shrink-0 text-nya-text-tertiary" aria-hidden="true" />
    </button>
    {#if from || to}
      <button
        type="button"
        aria-label="清除时间范围筛选"
        title="清除时间范围筛选"
        onclick={clearRange}
        class="flex w-10 shrink-0 items-center justify-center border-l border-nya-divider text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-danger focus:outline-none"
      ><X size={16} aria-hidden="true" /></button>
    {/if}
  </div>
</div>

<Modal bind:open title="选择时间范围" description="按本地时间选择，确认后转换为标准时间写入审计筛选" size="lg">
  <div class="space-y-5">
    <div class="flex flex-wrap items-center gap-2" aria-label="快捷时间范围">
      <span class="mr-1 text-small font-medium text-nya-text-secondary">距今</span>
      {#each quickRanges as days}
        <Button size="sm" variant="soft" onclick={() => setQuickRange(days)} ariaLabel={`最近 ${days} 天`}>{days} 天</Button>
      {/each}
    </div>

    <div class="grid gap-5 md:grid-cols-[minmax(0,1fr)_220px]">
      <section aria-labelledby={`${id}-calendar-title`}>
        <div class="mb-3 grid grid-cols-[auto_auto_1fr_auto_auto] items-center gap-1">
          <button type="button" onclick={() => moveMonth(-12)} aria-label="上一年" title="上一年" class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-secondary hover:bg-nya-surface-muted hover:text-nya-primary"><ChevronsLeft size={17} aria-hidden="true" /></button>
          <button type="button" onclick={() => moveMonth(-1)} aria-label="上个月" title="上个月" class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-secondary hover:bg-nya-surface-muted hover:text-nya-primary"><ChevronLeft size={17} aria-hidden="true" /></button>
          <h3 id={`${id}-calendar-title`} class="text-center text-card-title text-nya-text-primary">{monthTitle}</h3>
          <button type="button" onclick={() => moveMonth(1)} aria-label="下个月" title="下个月" class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-secondary hover:bg-nya-surface-muted hover:text-nya-primary"><ChevronRight size={17} aria-hidden="true" /></button>
          <button type="button" onclick={() => moveMonth(12)} aria-label="下一年" title="下一年" class="flex h-8 w-8 items-center justify-center rounded-nya-sm text-nya-text-secondary hover:bg-nya-surface-muted hover:text-nya-primary"><ChevronsRight size={17} aria-hidden="true" /></button>
        </div>

        <p class="mb-2 min-h-[19px] text-center text-small text-nya-text-secondary" aria-live="polite">{selectionHint}</p>
        <div class="grid grid-cols-7 gap-1" role="grid" aria-label={monthTitle}>
          {#each weekdays as weekday}
            <div class="flex h-7 items-center justify-center text-small font-medium text-nya-text-tertiary" role="columnheader">{weekday}</div>
          {/each}
          {#each calendarDays as day}
            <button
              type="button"
              class={dayClass(day)}
              onclick={() => chooseDay(day.dateKey)}
              aria-label={dayLabel(day)}
              aria-selected={day.dateKey === draftStartDate || (!endAtConfirmation && day.dateKey === draftEndDate)}
              aria-current={day.isToday ? 'date' : undefined}
              role="gridcell"
            >{day.day}</button>
          {/each}
        </div>
      </section>

      <section class="border-t border-nya-divider pt-4 md:border-l md:border-t-0 md:pl-5 md:pt-0" aria-label="精确时间">
        <div class="space-y-4">
          <TimePicker id={`${id}-start-time`} label="起始时间" bind:value={draftStartTime} {showSeconds} />
          <TimePicker id={`${id}-end-time`} label="结束时间" bind:value={draftEndTime} {showSeconds} disabled={endAtConfirmation} />
          <label class="flex cursor-pointer items-start gap-2.5 rounded-nya-sm bg-nya-surface-muted px-3 py-2.5 text-small text-nya-text-secondary">
            <input type="checkbox" bind:checked={endAtConfirmation} onchange={handleEndModeChange} class="mt-0.5 h-4 w-4 shrink-0 accent-[var(--nya-primary)]" />
            <span>结束时间使用确认时刻</span>
          </label>
          <div class="rounded-nya-sm border border-nya-border bg-nya-surface-subtle px-3 py-2.5 text-small text-nya-text-secondary">
            <p><span class="text-nya-text-tertiary">起始：</span>{draftStartDate || '未选择'} {draftStartDate ? draftStartTime : ''}</p>
            <p class="mt-1"><span class="text-nya-text-tertiary">结束：</span>{endAtConfirmation ? '确认时刻' : `${draftEndDate || '未选择'} ${draftEndDate ? draftEndTime : ''}`}</p>
          </div>
        </div>
      </section>
    </div>

    {#if validationError}
      <p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{validationError}</p>
    {/if}

    <div class="flex flex-wrap items-center justify-between gap-2 border-t border-nya-divider pt-4">
      <div>
        {#if from || to}
          <Button variant="ghost" onclick={clearRange}>清除时间筛选</Button>
        {/if}
      </div>
      <div class="flex gap-2">
        <Button variant="secondary" onclick={() => (open = false)}>取消</Button>
        <Button variant="primary" onclick={confirmRange}>确认并应用</Button>
      </div>
    </div>
  </div>
</Modal>
