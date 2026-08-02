import { ApiError } from "./client";

const LOCAL_SERVICE_UNAVAILABLE = "Could not reach the local service. Check that it is running and try again.";

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException
    ? error.name === "AbortError"
    : error instanceof Error && error.name === "AbortError";
}

export function safeOperationError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    if (error.status < 500 || error.code === "backend_unavailable") return error.message;
    return fallback;
  }
  if (error instanceof TypeError) return LOCAL_SERVICE_UNAVAILABLE;
  return fallback;
}
