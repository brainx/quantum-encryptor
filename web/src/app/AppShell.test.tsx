import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { READY_HEALTH } from "../test/fixtures";
import { AppShell } from "./AppShell";

it("exposes semantic navigation and changes workflows", async () => {
  const user = userEvent.setup();
  const onNavigate = vi.fn();

  render(
    <AppShell activeView="encrypt" health={READY_HEALTH} onNavigate={onNavigate}>
      <h1>Encrypt a file</h1>
    </AppShell>
  );

  expect(screen.getByRole("navigation", { name: "Workflows" })).toBeVisible();
  expect(screen.getByRole("button", { name: "Encrypt" })).toHaveAttribute("aria-current", "page");

  await user.click(screen.getByRole("button", { name: "Decrypt" }));

  expect(onNavigate).toHaveBeenCalledWith("decrypt");
  expect(screen.getByText("Local engine")).toBeVisible();
});

it("keeps a supplied availability reason in capability details", () => {
  const health = {
    ...READY_HEALTH,
    capabilities: {
      ...READY_HEALTH.capabilities,
      encrypt: {
        available: true,
        reason: "Uses the device-bound crypto provider."
      }
    }
  };

  render(
    <AppShell activeView="encrypt" health={health} onNavigate={() => undefined}>
      <h1>Encrypt a file</h1>
    </AppShell>
  );

  expect(screen.getAllByText("Uses the device-bound crypto provider.")).toHaveLength(2);
});

it("places narrow-layout workflow navigation before the main content in keyboard order", () => {
  render(
    <AppShell activeView="encrypt" health={READY_HEALTH} onNavigate={() => undefined}>
      <h1>Encrypt a file</h1>
    </AppShell>
  );

  const mobileNavigation = screen.getByRole("navigation", { name: "Mobile workflows" });
  const main = screen.getByRole("main");

  expect(mobileNavigation.compareDocumentPosition(main) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(mobileNavigation).toContainElement(screen.getByRole("link", { name: "Encrypt" }));
});
