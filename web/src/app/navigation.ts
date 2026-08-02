export type View = "encrypt" | "decrypt" | "generate" | "inspect";

export const NAV_ITEMS: ReadonlyArray<{ id: View; label: string }> = [
  { id: "encrypt", label: "Encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "generate", label: "Generate keys" },
  { id: "inspect", label: "Inspect key" }
];
