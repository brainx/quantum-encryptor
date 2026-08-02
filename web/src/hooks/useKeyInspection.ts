import { useEffect, useState } from "react";
import { inspectKey, type InspectKeyOperation, type KeyInspectResult } from "../api";

type KeyInspectionState = {
  sourceFile: File | null;
  result: KeyInspectResult | null;
  error: string | null;
  loading: boolean;
};

type KeyInspectionValue = Omit<KeyInspectionState, "sourceFile">;

const INITIAL_STATE: KeyInspectionState = {
  sourceFile: null,
  result: null,
  error: null,
  loading: false
};

function errorMessage(error: unknown): string {
  return error instanceof Error && error.message ? error.message : "Unable to inspect this key file.";
}

export function useKeyInspection(
  file: File | null,
  maxBytes: number,
  inspect: InspectKeyOperation = inspectKey
): KeyInspectionValue {
  const [state, setState] = useState<KeyInspectionState>(INITIAL_STATE);

  useEffect(() => {
    if (!file) {
      setState(INITIAL_STATE);
      return;
    }

    if (file.size > maxBytes) {
      setState({
        sourceFile: file,
        result: null,
        error: `This key file exceeds the ${maxBytes.toLocaleString()} byte limit.`,
        loading: false
      });
      return;
    }

    const controller = new AbortController();
    let current = true;
    setState({ sourceFile: file, result: null, error: null, loading: true });

    inspect(file, controller.signal)
      .then((result) => {
        if (!current || controller.signal.aborted) return;
        setState({ sourceFile: file, result, error: null, loading: false });
      })
      .catch((error: unknown) => {
        if (!current || controller.signal.aborted || (error instanceof Error && error.name === "AbortError")) return;
        setState({ sourceFile: file, result: null, error: errorMessage(error), loading: false });
      });

    return () => {
      current = false;
      controller.abort();
    };
  }, [file, inspect, maxBytes]);

  if (state.sourceFile !== file) {
    return {
      result: null,
      error: null,
      loading: file !== null && file.size <= maxBytes
    };
  }

  return {
    result: state.result,
    error: state.error,
    loading: state.loading
  };
}
