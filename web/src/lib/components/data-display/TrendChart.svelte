<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Chart, registerables } from 'chart.js';
  import type { TrendColor, TrendSeries } from '$lib/admin-stats';

  Chart.register(...registerables);

  let {
    labels = [],
    series = [],
    height = '220px',
    ariaLabel,
    emptyText = '暂无趋势数据',
  }: {
    labels: string[];
    series: TrendSeries[];
    height?: string;
    ariaLabel: string;
    emptyText?: string;
  } = $props();

  let canvas = $state<HTMLCanvasElement>();
  let chart: Chart | undefined;

  const colorTokens: Record<TrendColor, { variable: string; fallback: string }> = {
    primary: { variable: '--nya-primary', fallback: '#704de8' },
    blue: { variable: '--nya-blue', fallback: '#40a9f3' },
    mint: { variable: '--nya-mint', fallback: '#19c79a' },
    orange: { variable: '--nya-orange', fallback: '#ff9657' },
    pink: { variable: '--nya-pink', fallback: '#f56fa7' },
    danger: { variable: '--nya-danger', fallback: '#ec4b6f' },
  };

  function resolveColor(color: TrendColor): string {
    const token = colorTokens[color];
    return getComputedStyle(document.documentElement).getPropertyValue(token.variable).trim() || token.fallback;
  }

  function translucent(color: string): string {
    return /^#[0-9a-f]{6}$/i.test(color) ? `${color}20` : color;
  }

  function destroyChart() {
    chart?.destroy();
    chart = undefined;
  }

  function createChart() {
    if (!canvas || labels.length === 0 || series.length === 0) return;
    destroyChart();

    chart = new Chart(canvas, {
      type: 'line',
      data: {
        // Chart.js defines non-enumerable bookkeeping properties on these
        // arrays, which Svelte 5 $state proxies forbid — pass plain copies.
        labels: [...labels],
        datasets: series.map((item) => {
          const color = resolveColor(item.color);
          return {
            label: item.label,
            data: [...item.values],
            borderColor: color,
            backgroundColor: translucent(color),
            borderWidth: 2.5,
            fill: item.fill ?? false,
            tension: 0.3,
            pointBackgroundColor: '#ffffff',
            pointBorderColor: color,
            pointBorderWidth: 2,
            pointRadius: 3,
            pointHoverRadius: 5,
          };
        }),
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: {
            display: series.length > 1,
            labels: {
              color: '#686d80',
              boxWidth: 10,
              boxHeight: 10,
              usePointStyle: true,
              pointStyle: 'circle',
            },
          },
          tooltip: {
            backgroundColor: 'rgba(32, 34, 53, 0.9)',
            titleColor: '#fff',
            bodyColor: '#fff',
            cornerRadius: 8,
            padding: 10,
            displayColors: series.length > 1,
            callbacks: {
              label: (ctx) => `${ctx.dataset.label ?? '数量'}：${ctx.parsed.y ?? 0}`,
            },
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#9398ac', font: { size: 11 } },
            border: { display: false },
          },
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(233, 230, 241, 0.6)' },
            ticks: {
              color: '#9398ac',
              font: { size: 11 },
              precision: 0,
            },
            border: { display: false },
          },
        },
      },
    });
  }

  $effect(() => {
    labels;
    series;
    if (labels.length === 0 || series.length === 0) {
      destroyChart();
      return;
    }
    if (canvas) {
      const timer = setTimeout(createChart, 50);
      return () => clearTimeout(timer);
    }
  });

  onDestroy(destroyChart);
</script>

<div style="height: {height}; position: relative;">
  {#if labels.length > 0 && series.length > 0}
    <canvas bind:this={canvas} aria-label={ariaLabel}></canvas>
    <table class="sr-only">
      <caption>{ariaLabel}数据明细</caption>
      <thead>
        <tr>
          <th scope="col">日期</th>
          {#each series as item}
            <th scope="col">{item.label}</th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each labels as label, index}
          <tr>
            <th scope="row">{label}</th>
            {#each series as item}
              <td>{item.values[index] ?? 0}</td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  {:else}
    <div class="flex h-full flex-col items-center justify-center text-nya-text-tertiary">
      <p class="text-small">{emptyText}</p>
    </div>
  {/if}
</div>
