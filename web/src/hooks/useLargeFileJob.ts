import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";
import { isAbortError, safeOperationError } from "../api/errors";
import { largeFileOperations, type LargeFileJob, type LargeFileMode, type LargeFileOperations } from "../api/largeFiles";

type Run = {
  controller: AbortController;
  job: LargeFileJob | null;
  mode: LargeFileMode;
  credentials: { key: File; password: string } | null;
  cancelled: boolean;
  epoch: number;
  cleanupRequested: boolean;
  cleanupPromise: Promise<void> | null;
};
export const terminalJob = (job: LargeFileJob) => ["complete", "failed", "cancelled"].includes(job.state);
const EXPIRED = "The temporary job has expired. Select the file and run the operation again.";

export function useLargeFileJob(operations: LargeFileOperations = largeFileOperations) {
  const [job, setJob] = useState<LargeFileJob | null>(null);
  const [stage, setStage] = useState<"reserving" | "uploading" | "starting" | "cancelling" | "clearing" | null>(null);
  const [uploadBytes, setUploadBytes] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [pollingPaused, setPollingPaused] = useState(false);
  const [expired, setExpired] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const mounted = useRef(true);
  const active = useRef<Run | null>(null);
  const statusRequest = useRef<AbortController | null>(null);
  const changing = useRef(false);
  const mutation = useRef<Promise<unknown> | null>(null);

  const current = (run: Run) => mounted.current && active.current === run;
  const accept = useCallback((run: Run, next: LargeFileJob) => {
    if (!mounted.current || active.current !== run) return;
    if (next.mode !== run.mode || (run.job && next.id !== run.job.id)) throw new Error("Mismatched job status");
    run.job = next;
    if (terminalJob(next)) run.credentials = null;
    setJob(next);
  }, []);
  const fail = useCallback((caught: unknown) => {
    if (caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired") {
      active.current = null;
      setJob(null);
      setExpired(true);
      setRestoring(false);
      setPollingPaused(false);
      setStage(null);
      setError(EXPIRED);
      return;
    }
    setError(safeOperationError(caught, "The local service could not complete this request. Check the job status before trying again."));
  }, []);

  const refresh = useCallback(async () => {
    const run = active.current;
    if (!run?.job || statusRequest.current || changing.current) return;
    const epoch = run.epoch;
    const controller = new AbortController();
    statusRequest.current = controller;
    try {
      const next = await operations.status(run.job.id, controller.signal);
      if (!mounted.current || active.current !== run || epoch !== run.epoch || controller.signal.aborted) return;
      accept(run, next);
      setPollingPaused(false);
      setRestoring(false);
      setError(null);
    } catch (caught) {
      if (!mounted.current || active.current !== run || epoch !== run.epoch || isAbortError(caught)) return;
      setPollingPaused(true);
      fail(caught);
    } finally {
      if (statusRequest.current === controller) statusRequest.current = null;
    }
  }, [operations, accept, fail]);

  useEffect(() => {
    mounted.current = true;
    let hidden = false;
    let lifecycleEpoch = 0;
    function requestCleanup(run: Run | null) {
      statusRequest.current?.abort();
      statusRequest.current = null;
      if (!run) return;
      run.cancelled = true;
      run.epoch += 1;
      run.credentials = null;
      run.controller.abort();
      if (run.job && !run.cleanupRequested) {
        run.cleanupRequested = true;
        run.cleanupPromise = (async () => {
          // A user-initiated clear/cancel may already own cleanup. Let it settle first.
          if (mutation.current) await mutation.current.catch(() => {});
          if (!run.job) return;
          const cleanup = terminalJob(run.job) ? operations.clear : operations.cancel;
          await cleanup(run.job.id).catch(() => {});
        })();
      }
    }
    function pageHide() {
      hidden = true;
      lifecycleEpoch += 1;
      setRestoring(true);
      requestCleanup(active.current);
    }
    async function restoreStatus() {
      const epoch = lifecycleEpoch;
      const run = active.current;
      if (run?.cleanupPromise) await run.cleanupPromise;
      if (mutation.current) await mutation.current.catch(() => {});
      if (!mounted.current || epoch !== lifecycleEpoch) return;
      if (!run?.job || active.current !== run) { setRestoring(false); return; }
      run.cleanupRequested = false;
      setStage(null);
      // Revalidate only after cleanup settles; its acknowledgement may remove the result.
      await refresh();
    }
    function pageShow() {
      if (!hidden) return;
      hidden = false;
      void restoreStatus();
    }
    window.addEventListener("pagehide", pageHide);
    window.addEventListener("pageshow", pageShow);
    return () => {
      mounted.current = false;
      lifecycleEpoch += 1;
      const run = active.current;
      active.current = null;
      requestCleanup(run);
      window.removeEventListener("pagehide", pageHide);
      window.removeEventListener("pageshow", pageShow);
    };
  }, [operations, refresh]);

  useEffect(() => {
    if (!job || terminalJob(job) || stage || pollingPaused || restoring) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await refresh();
      if (!stopped) timer = setTimeout(poll, 1000);
    }
    timer = setTimeout(poll, 1000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [job?.id, job?.state, stage, pollingPaused, restoring, refresh]);

  useEffect(() => {
    if (!job || !terminalJob(job) || pollingPaused || restoring) return;
    const timer = setTimeout(() => void refresh(), Math.min(2_147_483_647, Math.max(0, Date.parse(job.expiresAt) - Date.now())));
    return () => clearTimeout(timer);
  }, [job?.id, job?.state, job?.expiresAt, pollingPaused, restoring, refresh]);

  async function cancelRun(run: Run) {
    if (!run.job) return;
    const next = await operations.cancel(run.job.id);
    if (current(run)) accept(run, next);
  }

  async function start(mode: LargeFileMode, file: File, key: File, password: string, expectedRecipientFingerprint?: string) {
    if (!mounted.current || active.current || changing.current) return;
    const run: Run = { controller: new AbortController(), job: null, mode, credentials: { key, password }, cancelled: false, epoch: 0, cleanupRequested: false, cleanupPromise: null };
    active.current = run;
    setError(null); setExpired(false); setRestoring(false); setPollingPaused(false); setUploadBytes(0); setStage("reserving");
    try {
      const reservation = await operations.create(mode, file, run.controller.signal);
      run.job = reservation;
      if (!current(run) || run.cancelled) {
        if (current(run)) {
          accept(run, reservation);
          try { await cancelRun(run); }
          catch (caught) { if (current(run)) { setPollingPaused(true); fail(caught); } }
        } else await operations.cancel(reservation.id).catch(() => {});
        return;
      }
      accept(run, reservation);
      setStage("uploading");
      const uploaded = await operations.upload(reservation.id, file, (loaded) => {
        if (current(run) && !run.cancelled) setUploadBytes(Math.min(loaded, file.size));
      }, run.controller.signal);
      if (!current(run) || run.cancelled) return;
      accept(run, uploaded);
      setStage("starting");
      const credentials = run.credentials;
      run.credentials = null;
      if (!credentials) return;
      const response = expectedRecipientFingerprint === undefined
        ? operations.start(reservation.id, credentials.key, credentials.password, run.controller.signal)
        : operations.start(reservation.id, credentials.key, credentials.password, run.controller.signal, expectedRecipientFingerprint);
      credentials.password = "";
      const started = await response;
      if (current(run) && !run.cancelled) accept(run, started);
    } catch (caught) {
      if (!current(run) || run.cancelled || isAbortError(caught)) return;
      setPollingPaused(true);
      fail(caught);
      if (!run.job) { active.current = null; setStage(null); }
    } finally {
      run.credentials = null;
      if (current(run)) {
        if (!run.cancelled || !changing.current) setStage(null);
        if (run.cancelled && !run.job) {
          active.current = null;
          setError("The request was stopped. Any abandoned server job will expire automatically.");
        }
      }
    }
  }

  async function cancel() {
    const run = active.current;
    if (!run || changing.current || restoring || (run.job && terminalJob(run.job))) return;
    run.cancelled = true;
    run.credentials = null;
    run.epoch += 1;
    run.controller.abort();
    statusRequest.current?.abort();
    statusRequest.current = null;
    setError(null); setPollingPaused(false); setStage("cancelling");
    if (!run.job) return;
    changing.current = true;
    const pending = cancelRun(run);
    mutation.current = pending;
    try { await pending; }
    catch (caught) { if (current(run)) { setPollingPaused(true); fail(caught); } }
    finally {
      if (mutation.current === pending) mutation.current = null;
      changing.current = false;
      if (current(run)) setStage(null);
    }
  }

  async function clear(): Promise<boolean> {
    const run = active.current;
    if (changing.current || restoring) return false;
    if (!run) { setJob(null); setExpired(false); setError(null); return true; }
    if (!run.job) return false;
    if (stage === "reserving" || stage === "uploading" || stage === "starting" || stage === "cancelling" ||
        (!terminalJob(run.job) && run.job.state !== "awaiting_upload" && run.job.state !== "ready")) return false;
    changing.current = true;
    run.epoch += 1;
    statusRequest.current?.abort();
    statusRequest.current = null;
    setStage("clearing");
    let pending: Promise<unknown> | null = null;
    try {
      pending = operations.clear(run.job.id);
      mutation.current = pending;
      await pending;
      if (!current(run)) return false;
      run.job = null;
      active.current = null;
      setJob(null); setError(null); setExpired(false); setRestoring(false); setPollingPaused(false);
      return true;
    } catch (caught) {
      if (current(run)) fail(caught);
      return caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired";
    } finally {
      if (mutation.current === pending) mutation.current = null;
      changing.current = false;
      if (mounted.current) setStage(null);
    }
  }

  return { job, stage, uploadBytes, error, expired, restoring, pollingPaused, start, cancel, clear, refresh };
}
