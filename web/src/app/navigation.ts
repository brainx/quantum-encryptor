export type View = "encrypt" | "batch-encrypt" | "decrypt" | "batch-decrypt" | "generate" | "change-password" | "inspect";

export const NAV_ITEMS: ReadonlyArray<{ id: View; label: string }> = [
  { id: "encrypt", label: "Encrypt" },
  { id: "batch-encrypt", label: "Batch encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "batch-decrypt", label: "Batch decrypt" },
  { id: "generate", label: "Generate keys" },
  { id: "change-password", label: "Change password" },
  { id: "inspect", label: "Inspect key" }
];
