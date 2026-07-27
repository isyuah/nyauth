<script lang="ts">
  import { onDestroy, tick } from 'svelte';
  import Button from '$lib/components/ui/Button.svelte';
  import Modal from '$lib/components/ui/Modal.svelte';
  import { ImagePlus, RotateCcw, Trash2, Upload } from 'lucide-svelte';

  interface Props {
    currentUrl?: string | null;
    disabled?: boolean;
    onupload: (blob: Blob) => Promise<void>;
    onremove?: () => Promise<void>;
  }

  let { currentUrl = null, disabled = false, onupload, onremove }: Props = $props();

  const maxBytes = 8 * 1024 * 1024;
  const cropSize = 640;
  const outputSize = 1024;
  const allowedTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);

  let open = $state(false);
  let canvas: HTMLCanvasElement;
  let circleCanvas: HTMLCanvasElement;
  let fileInput: HTMLInputElement;
  let bitmap: ImageBitmap | null = null;
  let zoom = $state(1);
  let rotation = $state(0);
  let offsetX = $state(0);
  let offsetY = $state(0);
  let dragging = false;
  let dragX = 0;
  let dragY = 0;
  let uploading = $state(false);
  let removing = $state(false);
  let error = $state('');
  let destroyed = false;

  onDestroy(() => {
    destroyed = true;
    bitmap?.close();
    bitmap = null;
  });

  function rotatedDimensions() {
    if (!bitmap) return { width: 1, height: 1 };
    return rotation % 180 === 0
      ? { width: bitmap.width, height: bitmap.height }
      : { width: bitmap.height, height: bitmap.width };
  }

  function scaleForCrop() {
    const dimensions = rotatedDimensions();
    return Math.max(cropSize / dimensions.width, cropSize / dimensions.height) * zoom;
  }

  function clampOffsets() {
    if (!bitmap) return;
    const dimensions = rotatedDimensions();
    const scale = scaleForCrop();
    const maxX = Math.max(0, (dimensions.width * scale - cropSize) / 2);
    const maxY = Math.max(0, (dimensions.height * scale - cropSize) / 2);
    offsetX = Math.max(-maxX, Math.min(maxX, offsetX));
    offsetY = Math.max(-maxY, Math.min(maxY, offsetY));
  }

  function drawTo(target: HTMLCanvasElement | undefined, size: number) {
    if (!target) return;
    const context = target.getContext('2d');
    if (!context) return;
    target.width = size;
    target.height = size;
    context.clearRect(0, 0, size, size);
    context.fillStyle = '#eef1f6';
    context.fillRect(0, 0, size, size);
    if (!bitmap) return;

    const ratio = size / cropSize;
    context.save();
    context.translate(size / 2 + offsetX * ratio, size / 2 + offsetY * ratio);
    context.rotate((rotation * Math.PI) / 180);
    const scale = scaleForCrop() * ratio;
    context.scale(scale, scale);
    context.drawImage(bitmap, -bitmap.width / 2, -bitmap.height / 2);
    context.restore();
  }

  function redraw() {
    clampOffsets();
    drawTo(canvas, cropSize);
    drawTo(circleCanvas, 128);
  }

  $effect(() => {
    zoom;
    rotation;
    offsetX;
    offsetY;
    if (open) queueMicrotask(redraw);
  });

  $effect(() => {
    if (!open && bitmap) releaseImage();
  });

  function releaseImage() {
    bitmap?.close();
    bitmap = null;
    if (canvas) drawTo(canvas, cropSize);
    if (circleCanvas) drawTo(circleCanvas, 128);
    if (fileInput) fileInput.value = '';
  }

  function closeEditor() {
    releaseImage();
    error = '';
    open = false;
  }

  async function chooseFile(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    error = '';
    if (file.size > maxBytes) {
      error = '图片不能超过 8 MiB。';
      input.value = '';
      return;
    }
    if (!allowedTypes.has(file.type)) {
      error = '请选择 JPEG、PNG 或静态 WebP 图片。';
      input.value = '';
      return;
    }
    try {
      const next = await createImageBitmap(file);
      if (destroyed) {
        next.close();
        return;
      }
      bitmap?.close();
      bitmap = next;
      zoom = 1;
      rotation = 0;
      offsetX = 0;
      offsetY = 0;
      open = true;
      await tick();
      redraw();
    } catch {
      error = '无法读取这张图片，请换一张后重试。';
      input.value = '';
    }
  }

  function pointerDown(event: PointerEvent) {
    if (!bitmap) return;
    dragging = true;
    dragX = event.clientX;
    dragY = event.clientY;
    canvas.setPointerCapture(event.pointerId);
  }

  function pointerMove(event: PointerEvent) {
    if (!dragging) return;
    const rect = canvas.getBoundingClientRect();
    const ratio = cropSize / rect.width;
    offsetX += (event.clientX - dragX) * ratio;
    offsetY += (event.clientY - dragY) * ratio;
    dragX = event.clientX;
    dragY = event.clientY;
  }

  function pointerUp(event: PointerEvent) {
    dragging = false;
    if (canvas.hasPointerCapture(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
  }

  function moveWithKeyboard(event: KeyboardEvent) {
    const step = event.shiftKey ? 24 : 8;
    if (event.key === 'ArrowLeft') offsetX -= step;
    else if (event.key === 'ArrowRight') offsetX += step;
    else if (event.key === 'ArrowUp') offsetY -= step;
    else if (event.key === 'ArrowDown') offsetY += step;
    else return;
    event.preventDefault();
  }

  function resetCrop() {
    zoom = 1;
    rotation = 0;
    offsetX = 0;
    offsetY = 0;
  }

  function canvasBlob(type: string): Promise<Blob | null> {
    const output = document.createElement('canvas');
    drawTo(output, outputSize);
    return new Promise((resolve) => output.toBlob(resolve, type, 0.9));
  }

  async function submit() {
    if (!bitmap) return;
    uploading = true;
    error = '';
    try {
      const webp = await canvasBlob('image/webp');
      const blob = webp && webp.type === 'image/webp' ? webp : await canvasBlob('image/png');
      if (!blob) throw new Error('图片编码失败');
      await onupload(blob);
      closeEditor();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '头像上传失败，请稍后重试。';
    } finally {
      uploading = false;
    }
  }

  async function removeCurrent() {
    if (!onremove) return;
    removing = true;
    error = '';
    try {
      await onremove();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : '头像删除失败，请稍后重试。';
    } finally {
      removing = false;
    }
  }
</script>

<div class="space-y-3">
  <div class="flex flex-wrap items-center gap-3">
    <label class="inline-flex cursor-pointer items-center gap-2 rounded-nya-sm border border-nya-border bg-nya-surface px-3 py-2 text-small font-semibold text-nya-text-primary hover:bg-nya-surface-muted aria-disabled:cursor-not-allowed aria-disabled:opacity-60" aria-disabled={disabled}>
      <ImagePlus size={16} /> 选择并裁剪头像
      <input bind:this={fileInput} type="file" accept="image/jpeg,image/png,image/webp" class="sr-only" disabled={disabled} onchange={chooseFile} />
    </label>
    {#if currentUrl && onremove}
      <Button variant="ghost" size="sm" disabled={disabled} loading={removing} onclick={removeCurrent}><Trash2 size={15} /> 删除头像</Button>
    {/if}
  </div>
  <p class="text-small text-nya-text-tertiary">支持 JPEG、PNG、静态 WebP，最大 8 MiB；原图不会保存。</p>
  {#if error && !open}<p class="rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
</div>

<Modal bind:open title="裁剪头像" description="拖动图片选择区域，或使用滑块调整缩放" size="lg">
  <div class="grid gap-5 md:grid-cols-[minmax(0,1fr)_160px]">
    <div>
      <button type="button" aria-label="头像裁剪区域，可拖动图片，或使用方向键移动图片，按住 Shift 可加速" onkeydown={moveWithKeyboard} class="block w-full max-w-[420px] rounded-nya-md p-0 outline-none focus:ring-2 focus:ring-nya-primary">
        <canvas
          bind:this={canvas}
          class="aspect-square w-full touch-none rounded-nya-md border border-nya-border bg-nya-surface-muted"
          onpointerdown={pointerDown}
          onpointermove={pointerMove}
          onpointerup={pointerUp}
          onpointercancel={pointerUp}
        ></canvas>
      </button>
      <div class="mt-4">
        <label for="avatar-zoom" class="mb-1.5 block text-small font-semibold text-nya-text-primary">缩放 {zoom.toFixed(2)}×</label>
        <input id="avatar-zoom" class="w-full accent-nya-primary" type="range" min="1" max="3" step="0.01" bind:value={zoom} />
      </div>
      <div class="mt-3 flex flex-wrap gap-2">
        <Button variant="secondary" size="sm" onclick={() => (rotation = (rotation + 90) % 360)}><RotateCcw size={15} /> 旋转 90°</Button>
        <Button variant="ghost" size="sm" onclick={resetCrop}>重置</Button>
      </div>
    </div>
    <div>
      <p class="mb-2 text-small font-semibold text-nya-text-primary">圆形预览</p>
      <div class="h-32 w-32 overflow-hidden rounded-full border border-nya-border bg-nya-surface-muted">
        <canvas bind:this={circleCanvas} class="h-full w-full" aria-label="头像圆形预览"></canvas>
      </div>
      <p class="mt-3 text-micro text-nya-text-tertiary">服务端还会重新校验并生成固定尺寸 WebP。</p>
    </div>
  </div>
  {#if error}<p class="mt-4 rounded-nya-sm bg-nya-danger-soft px-3 py-2 text-small text-nya-danger" role="alert">{error}</p>{/if}
  <div class="mt-5 flex justify-end gap-2">
    <Button variant="secondary" disabled={uploading} onclick={closeEditor}>取消</Button>
    <Button variant="primary" loading={uploading} onclick={submit}><Upload size={15} /> 上传头像</Button>
  </div>
</Modal>
