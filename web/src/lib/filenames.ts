export function suggestedEncryptedName(file: File | null): string {
  if (!file) return "encrypted-file.pqc";
  const dot = file.name.lastIndexOf(".");
  const stem = dot > 0 ? file.name.slice(0, dot) : file.name || "file";
  return `${stem}_encrypted.pqc`;
}

export function suggestedDecryptedName(file: File | null): string {
  if (!file) return "decrypted.bin";
  const name = file.name;
  if (name === ".pqc") return "decrypted.bin";
  if (name.endsWith("_encrypted.pqc")) {
    return name.slice(0, -"_encrypted.pqc".length) || "decrypted.bin";
  }
  if (name.endsWith(".pqc")) return `${name.slice(0, -".pqc".length)}_decrypted.bin`;
  const dot = name.lastIndexOf(".");
  if (dot > 0) return `${name.slice(0, dot)}_decrypted${name.slice(dot)}`;
  return `${name}_decrypted.bin`;
}
