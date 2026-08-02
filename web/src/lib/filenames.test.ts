import { describe, expect, it } from "vitest";
import { suggestedDecryptedName, suggestedEncryptedName } from "./filenames";

describe("filename suggestions", () => {
  it("creates the current encrypted filename convention", () => {
    expect(suggestedEncryptedName(new File(["x"], "report.pdf"))).toBe(
      "report_encrypted.pqc"
    );
  });

  it("recovers the original stem from the encrypted convention", () => {
    expect(suggestedDecryptedName(new File(["x"], "report_encrypted.pqc"))).toBe(
      "report"
    );
  });

  it("uses a safe fallback for a bare extension", () => {
    expect(suggestedDecryptedName(new File(["x"], ".pqc"))).toBe("decrypted.bin");
  });
});
