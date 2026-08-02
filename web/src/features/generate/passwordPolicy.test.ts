import { describe, expect, it } from "vitest";
import { passwordPolicyChecks } from "./passwordPolicy";

describe("passwordPolicyChecks", () => {
  it("reports the server-owned policy requirements and confirmation state", () => {
    expect(
      passwordPolicyChecks(
        "correct horse battery staple",
        "correct horse battery staple",
        { minChars: 16, minUniqueChars: 5 }
      )
    ).toEqual([
      { label: "16 or more characters", met: true },
      { label: "5 or more unique characters", met: true },
      { label: "Not a common password", met: true },
      { label: "Passwords match", met: true }
    ]);
  });

  it.each([
    "passwordpassword",
    "password12345678",
    "qwertyuiopasdfgh",
    "  PassWord 12345678  ",
    "Pass\u0085word12345678",
    "Pass\u001cword12345678"
  ])("matches the server normalization and rejects common password %j", (password) => {
    const checks = passwordPolicyChecks(password, password, { minChars: 16, minUniqueChars: 5 });

    expect(checks.find((check) => check.label === "Not a common password")).toEqual({
      label: "Not a common password",
      met: false
    });
  });
});
