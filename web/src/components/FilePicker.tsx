import type { ChangeEvent, DragEvent } from "react";
import { formatBytes } from "../lib/format";

export type FilePickerProps = {
  id: string;
  label: string;
  hint: string;
  accept?: string;
  file: File | null;
  error?: string;
  disabled?: boolean;
  onFile: (file: File | null) => void;
};

export function FilePicker({ id, label, hint, accept, file, error, disabled = false, onFile }: FilePickerProps) {
  const descriptionId = `${id}-description`;
  const errorId = `${id}-error`;
  const describedBy = error ? `${descriptionId} ${errorId}` : descriptionId;

  function selectFile(event: ChangeEvent<HTMLInputElement>) {
    if (disabled) return;
    onFile(event.target.files?.item(0) ?? null);
  }

  function allowDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
  }

  function dropFile(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    if (disabled) return;
    onFile(event.dataTransfer.files.item(0) ?? null);
  }

  return (
    <div className="file-picker-field">
      <label
        className={file ? "file-picker file-picker-selected" : "file-picker"}
        htmlFor={id}
        onDragOver={allowDrop}
        onDrop={dropFile}
      >
        <span className="file-picker-label">{label}</span>
        <span className="file-picker-prompt">Choose a file or drop it here</span>
        <span className="file-picker-selection">
          {file ? `${file.name} · ${formatBytes(file.size)}` : hint}
        </span>
        <input
          accept={accept}
          aria-label={label}
          aria-describedby={describedBy}
          className="file-picker-input"
          disabled={disabled}
          id={id}
          onChange={selectFile}
          type="file"
        />
      </label>
      <p className="field-hint" id={descriptionId}>
        {hint}
      </p>
      {error && (
        <p className="field-error" id={errorId} role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
