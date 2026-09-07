export type View = "encrypt" | "batch-encrypt" | "decrypt" | "generate" | "inspect";

export const NAV_ITEMS: ReadonlyArray<{ id: View; label: string }> = [
  { id: "encrypt", label: "Encrypt" },
  { id: "batch-encrypt", label: "Batch encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "generate", label: "Generate keys" },
  { id: "inspect", label: "Inspect key" }
];
