export type View = "encrypt" | "batch-encrypt" | "decrypt" | "batch-decrypt" | "large-files" | "generate" | "change-password" | "inspect" | "verify-file" | "recover-public";

export const NAV_ITEMS: ReadonlyArray<{ id: View; label: string }> = [
  { id: "encrypt", label: "Encrypt" },
  { id: "batch-encrypt", label: "Batch encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "batch-decrypt", label: "Batch decrypt" },
  { id: "large-files", label: "Large files" },
  { id: "verify-file", label: "Verify file" },
  { id: "generate", label: "Generate keys" },
  { id: "change-password", label: "Change password" },
  { id: "recover-public", label: "Recover public key" },
  { id: "inspect", label: "Inspect key" }
];
