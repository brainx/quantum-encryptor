import type { Health } from "../../api";

export type PasswordPolicyCheck = {
  label: string;
  met: boolean;
};

// Keep this usability check synchronized with crypto_core.COMMON_WEAK_PASSWORDS; the server remains authoritative.
const COMMON_WEAK_PASSWORDS = new Set([
  "passwordpassword",
  "password12345678",
  "qwertyuiopasdfgh"
]);
const PYTHON_SPLIT_WHITESPACE = /[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/gu;

function isCommonPassword(password: string): boolean {
  const normalized = password.toLowerCase().replace(PYTHON_SPLIT_WHITESPACE, "");
  return COMMON_WEAK_PASSWORDS.has(normalized);
}

export function passwordPolicyChecks(
  password: string,
  confirmation: string,
  policy: Health["passwordPolicy"]
): PasswordPolicyCheck[] {
  return [
    {
      label: `${policy.minChars} or more characters`,
      met: password.length >= policy.minChars
    },
    {
      label: `${policy.minUniqueChars} or more unique characters`,
      met: new Set(password).size >= policy.minUniqueChars
    },
    {
      label: "Not a common password",
      met: password.length > 0 && !isCommonPassword(password)
    },
    {
      label: "Passwords match",
      met: password.length > 0 && password === confirmation
    }
  ];
}
