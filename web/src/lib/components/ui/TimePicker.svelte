<script lang="ts">
  import { tick } from 'svelte';
  import { Popover } from 'bits-ui';
  import { Check, Clock3 } from 'lucide-svelte';
  import Button from './Button.svelte';

  type TimeSegment = 'hour' | 'minute' | 'second';
  type TimeParts = { hour: string; minute: string; second: string };

  let {
    id = 'time-picker',
    label = '时间',
    value = $bindable('00:00'),
    showSeconds = false,
    disabled = false,
    error = '',
  }: {
    id?: string;
    label?: string;
    value?: string;
    showSeconds?: boolean;
    disabled?: boolean;
    error?: string;
  } = $props();

  const hourOptions = Array.from({ length: 24 }, (_, index) => String(index).padStart(2, '0'));
  const minuteOptions = Array.from({ length: 60 }, (_, index) => String(index).padStart(2, '0'));

  function parseValue(candidate: string, includeSeconds: boolean): TimeParts | null {
    const match = /^(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(candidate);
    if (!match || (includeSeconds && match[3] === undefined) || (!includeSeconds && match[3] !== undefined)) return null;
    const parsedHour = Number(match[1]);
    const parsedMinute = Number(match[2]);
    const parsedSecond = Number(match[3] ?? '00');
    if (parsedHour > 23 || parsedMinute > 59 || parsedSecond > 59) return null;
    return { hour: match[1], minute: match[2], second: match[3] ?? '00' };
  }

  const initial = parseValue(value, value.length === 8) ?? { hour: '00', minute: '00', second: '00' };
  let hour = $state(initial.hour);
  let minute = $state(initial.minute);
  let second = $state(initial.second);
  let open = $state(false);
  let hourInput = $state<HTMLInputElement>();
  let minuteInput = $state<HTMLInputElement>();
  let secondInput = $state<HTMLInputElement>();

  let composedValue = $derived(`${hour}:${minute}${showSeconds ? `:${second}` : ''}`);

  $effect(() => {
    if (value === composedValue) return;
    const parsed = parseValue(value, showSeconds);
    if (!parsed) return;
    hour = parsed.hour;
    minute = parsed.minute;
    second = parsed.second;
  });

  function segmentValue(segment: TimeSegment): string {
    if (segment === 'hour') return hour;
    if (segment === 'minute') return minute;
    return second;
  }

  function segmentMax(segment: TimeSegment): number {
    return segment === 'hour' ? 23 : 59;
  }

  function segmentInput(segment: TimeSegment): HTMLInputElement | undefined {
    if (segment === 'hour') return hourInput;
    if (segment === 'minute') return minuteInput;
    return secondInput;
  }

  function nextSegment(segment: TimeSegment): TimeSegment | null {
    if (segment === 'hour') return 'minute';
    if (segment === 'minute' && showSeconds) return 'second';
    return null;
  }

  function previousSegment(segment: TimeSegment): TimeSegment | null {
    if (segment === 'second') return 'minute';
    if (segment === 'minute') return 'hour';
    return null;
  }

  function assignSegment(segment: TimeSegment, next: string) {
    if (segment === 'hour') hour = next;
    else if (segment === 'minute') minute = next;
    else second = next;
    value = `${hour}:${minute}${showSeconds ? `:${second}` : ''}`;
  }

  function focusSegment(segment: TimeSegment | null) {
    if (!segment) return;
    const input = segmentInput(segment);
    input?.focus();
    input?.select();
  }

  async function focusNextSegment(segment: TimeSegment) {
    const next = nextSegment(segment);
    if (!next) return;
    await tick();
    focusSegment(next);
  }

  function handleBeforeInput(event: InputEvent) {
    if (event.data && /\D/.test(event.data)) event.preventDefault();
  }

  function handleInput(segment: TimeSegment, event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const next = input.value.replace(/\D/g, '').slice(0, 2);
    if (input.value !== next) input.value = next;
    assignSegment(segment, next);
    if (next.length === 2 && Number(next) <= segmentMax(segment)) {
      void focusNextSegment(segment);
    }
  }

  function normalizeSegment(segment: TimeSegment) {
    const current = segmentValue(segment);
    if (!/^\d{1,2}$/.test(current)) return;
    const parsed = Number(current);
    if (parsed > segmentMax(segment)) return;
    assignSegment(segment, String(parsed).padStart(2, '0'));
  }

  function stepSegment(segment: TimeSegment, delta: number) {
    const current = Number(segmentValue(segment));
    const max = segmentMax(segment);
    const base = Number.isInteger(current) && current >= 0 && current <= max ? current : 0;
    assignSegment(segment, String((base + delta + max + 1) % (max + 1)).padStart(2, '0'));
    queueMicrotask(() => focusSegment(segment));
  }

  function handleKeydown(segment: TimeSegment, event: KeyboardEvent) {
    if (!event.ctrlKey && !event.metaKey && !event.altKey && event.key.length === 1 && !/^\d$/.test(event.key)) {
      event.preventDefault();
      return;
    }
    if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
      event.preventDefault();
      stepSegment(segment, event.key === 'ArrowUp' ? 1 : -1);
      return;
    }
    if (event.key === 'ArrowLeft' && (event.currentTarget as HTMLInputElement).selectionStart === 0) {
      const previous = previousSegment(segment);
      if (previous) {
        event.preventDefault();
        focusSegment(previous);
      }
      return;
    }
    if (event.key === 'ArrowRight') {
      const input = event.currentTarget as HTMLInputElement;
      if (input.selectionStart === input.value.length) {
        const next = nextSegment(segment);
        if (next) {
          event.preventDefault();
          focusSegment(next);
        }
      }
      return;
    }
    if (event.key === 'Backspace' && segmentValue(segment) === '') {
      const previous = previousSegment(segment);
      if (previous) {
        event.preventDefault();
        focusSegment(previous);
      }
    }
  }

  function invalidSegment(segment: TimeSegment): boolean {
    const current = segmentValue(segment);
    return /^\d{1,2}$/.test(current) && Number(current) > segmentMax(segment);
  }

  function chooseSegment(segment: TimeSegment, next: string) {
    assignSegment(segment, next);
  }

  function chooseCurrentTime() {
    const now = new Date();
    hour = String(now.getHours()).padStart(2, '0');
    minute = String(now.getMinutes()).padStart(2, '0');
    second = String(now.getSeconds()).padStart(2, '0');
    value = `${hour}:${minute}${showSeconds ? `:${second}` : ''}`;
  }
</script>

<div class="flex flex-col gap-1.5">
  <span id={`${id}-label`} class="text-body-medium text-nya-text-primary">{label}</span>
  <div
    class="flex h-[38px] w-full items-stretch overflow-hidden rounded-nya-sm border bg-nya-surface transition-all focus-within:border-nya-primary focus-within:ring-2 focus-within:ring-nya-primary/24 {error || invalidSegment('hour') || invalidSegment('minute') || (showSeconds && invalidSegment('second')) ? 'border-nya-danger' : 'border-nya-border hover:border-nya-border-strong'} {disabled ? 'cursor-not-allowed bg-nya-surface-soft text-nya-text-disabled' : ''}"
    role="group"
    aria-labelledby={`${id}-label`}
  >
    <div class="flex min-w-0 flex-1 items-center justify-center px-2 font-mono text-body text-nya-text-primary">
      <input
        bind:this={hourInput}
        id={`${id}-hour`}
        type="text"
        inputmode="numeric"
        pattern="[0-9]*"
        maxlength="2"
        value={hour}
        {disabled}
        aria-label={`${label}小时`}
        aria-invalid={invalidSegment('hour') ? 'true' : undefined}
        onbeforeinput={handleBeforeInput}
        oninput={(event) => handleInput('hour', event)}
        onblur={() => normalizeSegment('hour')}
        onkeydown={(event) => handleKeydown('hour', event)}
        onfocus={(event) => event.currentTarget.select()}
        class="h-full w-8 appearance-none border-0 bg-transparent p-0 text-center outline-none focus:border-0 focus:outline-none focus:ring-0 disabled:cursor-not-allowed"
      />
      <span class="px-0.5 text-nya-text-tertiary" aria-hidden="true">:</span>
      <input
        bind:this={minuteInput}
        id={`${id}-minute`}
        type="text"
        inputmode="numeric"
        pattern="[0-9]*"
        maxlength="2"
        value={minute}
        {disabled}
        aria-label={`${label}分钟`}
        aria-invalid={invalidSegment('minute') ? 'true' : undefined}
        onbeforeinput={handleBeforeInput}
        oninput={(event) => handleInput('minute', event)}
        onblur={() => normalizeSegment('minute')}
        onkeydown={(event) => handleKeydown('minute', event)}
        onfocus={(event) => event.currentTarget.select()}
        class="h-full w-8 appearance-none border-0 bg-transparent p-0 text-center outline-none focus:border-0 focus:outline-none focus:ring-0 disabled:cursor-not-allowed"
      />
      {#if showSeconds}
        <span class="px-0.5 text-nya-text-tertiary" aria-hidden="true">:</span>
        <input
          bind:this={secondInput}
          id={`${id}-second`}
          type="text"
          inputmode="numeric"
          pattern="[0-9]*"
          maxlength="2"
          value={second}
          {disabled}
          aria-label={`${label}秒`}
          aria-invalid={invalidSegment('second') ? 'true' : undefined}
          onbeforeinput={handleBeforeInput}
          oninput={(event) => handleInput('second', event)}
          onblur={() => normalizeSegment('second')}
          onkeydown={(event) => handleKeydown('second', event)}
          onfocus={(event) => event.currentTarget.select()}
          class="h-full w-8 appearance-none border-0 bg-transparent p-0 text-center outline-none focus:border-0 focus:outline-none focus:ring-0 disabled:cursor-not-allowed"
        />
      {/if}
    </div>

    <Popover.Root bind:open>
      <Popover.Trigger
        type="button"
        {disabled}
        aria-label={`选择${label}`}
        class="flex w-10 shrink-0 items-center justify-center border-l border-nya-divider text-nya-text-tertiary transition-colors hover:bg-nya-surface-muted hover:text-nya-primary focus:outline-none disabled:cursor-not-allowed disabled:text-nya-text-disabled"
      >
        <Clock3 size={16} aria-hidden="true" />
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          sideOffset={6}
          align="end"
          role="dialog"
          aria-label={`选择${label}`}
          class="z-[90] max-w-[calc(100vw-2rem)] rounded-nya-md border border-nya-border bg-nya-surface p-3 shadow-nya-popup outline-none"
        >
          <div class="grid gap-3 {showSeconds ? 'w-[430px] grid-cols-3' : 'w-[310px] grid-cols-2'} max-w-full">
            <section aria-label="小时选项">
              <p class="mb-2 text-center text-small font-medium text-nya-text-secondary">小时</p>
              <div class="grid max-h-48 grid-cols-4 gap-1 overflow-y-auto pr-1" role="listbox" aria-label={`${label}小时选项`}>
                {#each hourOptions as option}
                  <button
                    type="button"
                    role="option"
                    aria-selected={hour === option}
                    aria-label={`小时 ${option}`}
                    onclick={() => chooseSegment('hour', option)}
                    class="flex h-8 items-center justify-center rounded-nya-sm font-mono text-small transition-colors {hour === option ? 'bg-nya-primary text-white' : 'text-nya-text-primary hover:bg-nya-surface-muted'}"
                  >{option}</button>
                {/each}
              </div>
            </section>
            <section aria-label="分钟选项">
              <p class="mb-2 text-center text-small font-medium text-nya-text-secondary">分钟</p>
              <div class="grid max-h-48 grid-cols-5 gap-1 overflow-y-auto pr-1" role="listbox" aria-label={`${label}分钟选项`}>
                {#each minuteOptions as option}
                  <button
                    type="button"
                    role="option"
                    aria-selected={minute === option}
                    aria-label={`分钟 ${option}`}
                    onclick={() => chooseSegment('minute', option)}
                    class="flex h-8 items-center justify-center rounded-nya-sm font-mono text-small transition-colors {minute === option ? 'bg-nya-primary text-white' : 'text-nya-text-primary hover:bg-nya-surface-muted'}"
                  >{option}</button>
                {/each}
              </div>
            </section>
            {#if showSeconds}
              <section aria-label="秒选项">
                <p class="mb-2 text-center text-small font-medium text-nya-text-secondary">秒</p>
                <div class="grid max-h-48 grid-cols-5 gap-1 overflow-y-auto pr-1" role="listbox" aria-label={`${label}秒选项`}>
                  {#each minuteOptions as option}
                    <button
                      type="button"
                      role="option"
                      aria-selected={second === option}
                      aria-label={`秒 ${option}`}
                      onclick={() => chooseSegment('second', option)}
                      class="flex h-8 items-center justify-center rounded-nya-sm font-mono text-small transition-colors {second === option ? 'bg-nya-primary text-white' : 'text-nya-text-primary hover:bg-nya-surface-muted'}"
                    >{option}</button>
                  {/each}
                </div>
              </section>
            {/if}
          </div>
          <div class="mt-3 flex items-center justify-between border-t border-nya-divider pt-3">
            <Button size="sm" variant="ghost" onclick={chooseCurrentTime}>现在</Button>
            <Button size="sm" variant="primary" onclick={() => (open = false)}>
              <Check size={14} aria-hidden="true" />
              完成
            </Button>
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  </div>
  {#if error}
    <p class="text-small text-nya-danger" role="alert">{error}</p>
  {/if}
</div>
