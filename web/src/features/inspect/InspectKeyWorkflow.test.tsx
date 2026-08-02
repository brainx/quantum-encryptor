import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { READY_HEALTH } from "../../test/fixtures";
import { InspectKeyWorkflow } from "./InspectKeyWorkflow";

describe("InspectKeyWorkflow", () => {
  it("shows a safe key summary without rendering uploaded key material", async () => {
    const inspect = vi.fn().mockResolvedValue({
      ok: true,
      keyInfo: {
        kem: "ML-KEM-768+X25519-v2",
        key_type: "public"
      },
      display: {
        "Key Type": "Public",
        Algorithm: "ML-KEM-768+X25519-v2"
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
    expect(screen.queryByText("PEM")).not.toBeInTheDocument();
  });
});
