import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FilePicker } from "./FilePicker";
import { PasswordField } from "./PasswordField";
import { TechnicalDetails } from "./TechnicalDetails";

describe("shared controls", () => {
  it("selects a file through the labeled native input", async () => {
    const user = userEvent.setup();
    const onFile = vi.fn();
    render(
      <FilePicker
        id="plain-file"
        label="File to protect"
        hint="100 MiB maximum"
        file={null}
        onFile={onFile}
      />
    );
    const file = new File(["hello"], "hello.txt", { type: "text/plain" });
    await user.upload(screen.getByLabelText("File to protect"), file);
    expect(onFile).toHaveBeenCalledWith(file);
  });

  it("displays selected file sizes with the shared binary precision", () => {
    const file = new File([new Uint8Array(1024)], "key.pem", { type: "application/x-pem-file" });
    render(
      <FilePicker
        id="key-file"
        label="Key file"
        hint="128 KiB maximum"
        file={file}
        onFile={() => undefined}
      />
    );
    expect(screen.getByText("key.pem · 1.00 KiB")).toBeVisible();
  });

  it("keeps the visually hidden native file input in keyboard focus order", async () => {
    const user = userEvent.setup();
    render(
      <FilePicker
        id="keyboard-file"
        label="Keyboard file"
        hint="Select locally"
        file={null}
        onFile={() => undefined}
      />
    );

    await user.tab();

    expect(screen.getByLabelText("Keyboard file")).toHaveFocus();
  });

  it("announces password visibility through the button label", async () => {
    const user = userEvent.setup();
    render(
      <PasswordField
        id="password"
        label="Private key password"
        value="correct horse battery staple"
        onChange={() => undefined}
        autoComplete="current-password"
      />
    );
    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(screen.getByLabelText("Private key password")).toHaveAttribute("type", "text");
    expect(screen.getByRole("button", { name: "Hide password" })).toBeVisible();
  });

  it("uses a native disclosure with accurate expanded state", async () => {
    const user = userEvent.setup();
    render(
      <TechnicalDetails>
        <span>ML-KEM-768 + X25519</span>
      </TechnicalDetails>
    );
    await user.click(screen.getByText("Technical details"));
    expect(screen.getByText("ML-KEM-768 + X25519")).toBeVisible();
  });
});
