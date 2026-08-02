import type { DownloadResult } from "../api/contracts";

export function downloadBlob(result: DownloadResult): void {
  const url = URL.createObjectURL(result.blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = result.filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function downloadText(filename: string, text: string): void {
  downloadBlob({
    filename,
    blob: new Blob([text], { type: "application/x-pem-file" })
  });
}
