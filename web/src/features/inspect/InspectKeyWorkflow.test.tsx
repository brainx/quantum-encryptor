import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { READY_HEALTH } from "../../test/fixtures";
import { InspectKeyWorkflow } from "./InspectKeyWorkflow";

const TEST_PUBLIC_KEY_FINGERPRINT = `QE1-SHA3-256:${"a".repeat(64)}`;

describe("InspectKeyWorkflow", () => {
  it("shows a safe key summary without rendering uploaded key material", async () => {
    const inspect = vi.fn().mockResolvedValue({
      ok: true,
      keyInfo: {
        kem: "ML-KEM-768+X25519-v2",
        key_type: "public",
        public_key_fingerprint: TEST_PUBLIC_KEY_FINGERPRINT
      },
      display: {
        "Key Type": "Public",
        Algorithm: "ML-KEM-768+X25519-v2",
        "Public Key Fingerprint": TEST_PUBLIC_KEY_FINGERPRINT
      }
    });

    const user = userEvent.setup();
    render(<InspectKeyWorkflow health={READY_HEALTH} inspect={inspect} />);
    await user.upload(
      screen.getByLabelText("Key file"),
      new File(["PEM"], "recipient.pem", { type: "application/x-pem-file" })
    );

    expect(await screen.findByText("Public key")).toBeVisible();
    await user.click(screen.getByText("Technical details"));
    expect(screen.getByText("ML-KEM-768+X25519-v2")).toBeVisible();
    expect(screen.getByText(TEST_PUBLIC_KEY_FINGERPRINT)).toBeVisible();
    expect(screen.queryByText("PEM")).not.toBeInTheDocument();
  });

  it("does not invent a public-key fingerprint for metadata-only private inspection", async () => {
    const inspect = vi.fn().mockResolvedValue({
      ok: true,
      keyInfo: {
        kem: "ML-KEM-768+X25519-v2",
        key_type: "private",
        private_key_encrypted: true,
        private_key_format_version: 3,
        private_key_kdf: "scrypt"
      },
      display: {
        "Key Type": "Private",
        Algorithm: "ML-KEM-768+X25519-v2",
        "Password Encrypted": "Yes",
        "Private Key Format": "3",
        KDF: "scrypt"
      }
    });

    const user = userEvent.setup();
    render(<InspectKeyWorkflow health={READY_HEALTH} inspect={inspect} />);
    await user.upload(
      screen.getByLabelText("Key file"),
      new File(["PRIVATE-PEM"], "recipient-private.pem", { type: "application/x-pem-file" })
    );

    expect(await screen.findByText("Encrypted private key")).toBeVisible();
    await user.click(screen.getByText("Technical details"));
    expect(screen.getByText("scrypt")).toBeVisible();
    expect(screen.queryByText(TEST_PUBLIC_KEY_FINGERPRINT)).not.toBeInTheDocument();
    expect(screen.queryByText("Public Key Fingerprint")).not.toBeInTheDocument();
    expect(screen.queryByText("PRIVATE-PEM")).not.toBeInTheDocument();
  });
});
