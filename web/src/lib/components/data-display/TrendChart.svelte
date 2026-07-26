<script lang="ts">
  import { onDestroy } from 'svelte';
  import { Chart, registerables } from 'chart.js';

  Chart.register(...registerables);

  let {
    labels = [],
    values = [],
    height = '220px',
  }: {
    labels: string[];
    values: number[];
    height?: string;
  } = $props();

  let canvas = $state<HTMLCanvasElement>();
  let chart: Chart | undefined;

  function createChart() {
    if (!canvas || !labels.length) return;
    if (chart) chart.destroy();

    const primaryColor = getComputedStyle(document.documentElement).getPropertyValue('--nya-primary').trim() || '#7c5cff';

    chart = new Chart(canvas, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: '登录次数',
          data: values,
          borderColor: primaryColor,
          backgroundColor: primaryColor + '20',
          borderWidth: 2.5,
          fill: true,
          tension: 0.3,
          pointBackgroundColor: '#ffffff',
          pointBorderColor: primaryColor,
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { intersect: false, mode: 'index' },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(32, 34, 53, 0.9)',
            titleColor: '#fff',
            bodyColor: '#fff',
            cornerRadius: 8,
            padding: 10,
            displayColors: false,
            callbacks: {
              label: (ctx) => `${ctx.parsed.y} 次登录`,
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
    // Reactively recreate chart when data changes
    labels;
    values;
    if (canvas) {
      const timer = setTimeout(createChart, 50);
      return () => clearTimeout(timer);
    }
  });

  onDestroy(() => {
    if (chart) chart.destroy();
  });
</script>

<div style="height: {height}; position: relative;">
  {#if labels.length > 0 && values.some(v => v > 0)}
    <canvas bind:this={canvas}></canvas>
  {:else}
    <div class="flex flex-col items-center justify-center h-full" style="color: var(--nya-text-tertiary);">
      <p style="font-size: 13px;">暂无登录数据</p>
    </div>
  {/if}
</div>
