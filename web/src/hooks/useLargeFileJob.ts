import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";
import { isAbortError, safeOperationError } from "../api/errors";
import { largeFileOperations, type LargeFileJob, type LargeFileMode, type LargeFileOperations } from "../api/largeFiles";
import { readLargeFileRecovery, removeLargeFileRecovery, saveLargeFileRecovery } from "../lib/largeFileRecovery";

type Run = {
  controller: AbortController;
  job: LargeFileJob | null;
  mode: LargeFileMode;
  credentials: { key: File; password: string } | null;
  cancelled: boolean;
  epoch: number;
  cleanupRequested: boolean;
  cleanupPromise: Promise<void> | null;
  recoverable: boolean;
};
export const terminalJob = (job: LargeFileJob) => ["complete", "failed", "cancelled"].includes(job.state);
const EXPIRED = "The temporary job has expired. Select the file and run the operation again.";
const STORAGE_UNAVAILABLE = "This browser could not save the temporary job ID. Leaving this page will request cleanup.";
// Route changes can mount a new hook while the previous instance finishes a user action.
const pendingMutations = new Map<string, Promise<unknown>>();
function trackMutation(id: string, pending: Promise<unknown>) {
  pendingMutations.set(id, pending);
  const settled = () => { if (pendingMutations.get(id) === pending) pendingMutations.delete(id); };
  void pending.then(settled, settled);
}

export function useLargeFileJob(operations: LargeFileOperations = largeFileOperations) {
  const [initialRecoveryId] = useState(readLargeFileRecovery);
  const [recoveryEnabled, setRecoveryEnabledState] = useState(Boolean(initialRecoveryId));
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const [canRecover, setCanRecover] = useState(Boolean(initialRecoveryId));
  const [recovered, setRecovered] = useState(false);
  const [recoveryPending, setRecoveryPending] = useState(Boolean(initialRecoveryId));
  const recoveryEnabledRef = useRef(recoveryEnabled);
  const pendingRecoveryId = useRef(initialRecoveryId);
  const pendingRestoration = useRef(Boolean(initialRecoveryId));
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

  function setRecoveryEnabled(enabled: boolean) {
    if (active.current || pendingRecoveryId.current || changing.current) return;
    recoveryEnabledRef.current = enabled;
    setRecoveryEnabledState(enabled);
    setRecoveryError(null);
  }

  const current = (run: Run) => mounted.current && active.current === run;
  const accept = useCallback((run: Run, next: LargeFileJob) => {
    if (!mounted.current || active.current !== run) return;
    if (next.mode !== run.mode || (run.job && next.id !== run.job.id)) throw new Error("Mismatched job status");
    run.job = next;
    if (terminalJob(next)) run.credentials = null;
    setJob(next);
  }, []);
  const fail = useCallback((caught: unknown, id?: string) => {
    if (caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired") {
      if (id) removeLargeFileRecovery(id);
      pendingRecoveryId.current = null;
      pendingRestoration.current = false;
      active.current = null;
      setCanRecover(false);
      setRecoveryPending(false);
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
    const id = run?.job?.id ?? pendingRecoveryId.current;
    if (!id || statusRequest.current || changing.current) return;
    const epoch = run?.epoch;
    const controller = new AbortController();
    statusRequest.current = controller;
    const isCurrent = () => mounted.current && active.current === run && epoch === run?.epoch &&
      !controller.signal.aborted && (run !== null || pendingRecoveryId.current === id);
    if (!run || pendingRestoration.current) setRestoring(true);
    try {
      const pending = pendingMutations.get(id);
      if (pending) await pending.catch(() => {});
      if (!isCurrent()) return;
      const next = await operations.status(id, controller.signal);
      if (!isCurrent()) return;
      if (next.id !== id || !["encrypt", "decrypt", "verify"].includes(next.mode)) throw new Error("Mismatched job status");
      let attached = run;
      if (!attached) {
        attached = { controller: new AbortController(), job: null, mode: next.mode, credentials: null,
          cancelled: true, epoch: 0, cleanupRequested: false, cleanupPromise: null, recoverable: true };
        active.current = attached;
        pendingRecoveryId.current = null;
      }
      accept(attached, next);
      if (!run || pendingRestoration.current) setRecovered(true);
      setCanRecover(attached.recoverable && readLargeFileRecovery() === id);
      pendingRestoration.current = false;
      setRecoveryPending(false);
      setPollingPaused(false);
      setError(null);
    } catch (caught) {
      if (!isCurrent() || isAbortError(caught)) return;
      setPollingPaused(true);
      fail(caught, id);
    } finally {
      if (statusRequest.current === controller) {
        statusRequest.current = null;
        if (mounted.current) setRestoring(false);
      }
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
      if (run.recoverable && run.job && readLargeFileRecovery() === run.job.id) return;
      if (run.job && !run.cleanupRequested) {
        run.cleanupRequested = true;
        run.cleanupPromise = (async () => {
          // A user-initiated clear/cancel may already own cleanup. Let it settle first.
          if (mutation.current) await mutation.current.catch(() => {});
          if (!run.job) return;
          const id = run.job.id;
          const clearing = terminalJob(run.job);
          try {
            await (clearing ? operations.clear(id) : operations.cancel(id));
            if (clearing) removeLargeFileRecovery(id);
          } catch (caught) {
            if (caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired") removeLargeFileRecovery(id);
          }
        })();
      }
    }
    function pageHide() {
      hidden = true;
      lifecycleEpoch += 1;
      setRestoring(true);
      if (active.current?.job || pendingRecoveryId.current) {
        pendingRestoration.current = true;
        setRecoveryPending(true);
      }
      requestCleanup(active.current);
    }
    async function restoreStatus() {
      const epoch = lifecycleEpoch;
      const run = active.current;
      if (run?.cleanupPromise) await run.cleanupPromise;
      if (mutation.current) await mutation.current.catch(() => {});
      if (!mounted.current || epoch !== lifecycleEpoch) return;
      if ((!run?.job && !pendingRecoveryId.current) || active.current !== run) {
        pendingRestoration.current = false;
        setRestoring(false); setRecoveryPending(false); return;
      }
      if (run) run.cleanupRequested = false;
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
    if (pendingRecoveryId.current) void refresh();
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
    if (!job || terminalJob(job) || stage || pollingPaused || restoring || recoveryPending) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await refresh();
      if (!stopped) timer = setTimeout(poll, 1000);
    }
    timer = setTimeout(poll, 1000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [job?.id, job?.state, stage, pollingPaused, restoring, recoveryPending, refresh]);

  useEffect(() => {
    if (!job || !terminalJob(job) || pollingPaused || restoring || recoveryPending) return;
    const timer = setTimeout(() => void refresh(), Math.min(2_147_483_647, Math.max(0, Date.parse(job.expiresAt) - Date.now())));
    return () => clearTimeout(timer);
  }, [job?.id, job?.state, job?.expiresAt, pollingPaused, restoring, recoveryPending, refresh]);

  async function cancelRun(run: Run) {
    if (!run.job) return;
    const next = await operations.cancel(run.job.id);
    if (current(run)) accept(run, next);
  }

  async function start(mode: LargeFileMode, file: File, key: File, password: string, expectedRecipientFingerprint?: string) {
    if (!mounted.current || active.current || pendingRecoveryId.current || changing.current) return;
    const run: Run = { controller: new AbortController(), job: null, mode, credentials: { key, password }, cancelled: false, epoch: 0, cleanupRequested: false, cleanupPromise: null, recoverable: false };
    active.current = run;
    pendingRestoration.current = false;
    setError(null); setExpired(false); setRestoring(false); setRecoveryPending(false); setRecovered(false); setCanRecover(false); setRecoveryError(null);
    setPollingPaused(false); setUploadBytes(0); setStage("reserving");
    try {
      const reservation = await operations.create(mode, file, run.controller.signal);
      run.job = reservation;
      if (!current(run) || run.cancelled) {
        if (current(run)) {
          accept(run, reservation);
          try { await cancelRun(run); }
          catch (caught) { if (current(run)) { setPollingPaused(true); fail(caught, reservation.id); } }
        } else await operations.cancel(reservation.id).catch(() => {});
        return;
      }
      accept(run, reservation);
      if (recoveryEnabledRef.current) {
        run.recoverable = saveLargeFileRecovery(reservation.id);
        setCanRecover(run.recoverable);
        if (!run.recoverable) setRecoveryError(STORAGE_UNAVAILABLE);
      }
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
      fail(caught, run.job?.id);
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
    if (!run || changing.current || restoring || recoveryPending || (run.job && terminalJob(run.job))) return;
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
    trackMutation(run.job.id, pending);
    try { await pending; }
    catch (caught) {
      if (caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired" && run.job) removeLargeFileRecovery(run.job.id);
      if (current(run)) { setPollingPaused(true); fail(caught, run.job?.id); }
    }
    finally {
      if (mutation.current === pending) mutation.current = null;
      changing.current = false;
      if (current(run)) setStage(null);
    }
  }

  async function clear(): Promise<boolean> {
    const run = active.current;
    if (changing.current || restoring || recoveryPending) return false;
    if (!run) { setJob(null); setExpired(false); setError(null); setRecovered(false); return true; }
    if (!run.job) return false;
    if (stage === "reserving" || stage === "uploading" || stage === "starting" || stage === "cancelling" ||
        (!terminalJob(run.job) && run.job.state !== "awaiting_upload" && run.job.state !== "ready")) return false;
    changing.current = true;
    run.epoch += 1;
    statusRequest.current?.abort();
    statusRequest.current = null;
    setStage("clearing");
    let pending: Promise<unknown> | null = null;
    const id = run.job.id;
    try {
      pending = operations.clear(id);
      mutation.current = pending;
      trackMutation(id, pending);
      await pending;
      removeLargeFileRecovery(id);
      run.job = null;
      if (!current(run)) return false;
      active.current = null;
      pendingRestoration.current = false;
      setCanRecover(false); setRecoveryPending(false); setRecovered(false); setRecoveryError(null);
      setJob(null); setError(null); setExpired(false); setRestoring(false); setPollingPaused(false);
      return true;
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired") removeLargeFileRecovery(id);
      if (current(run)) fail(caught, id);
      return caught instanceof ApiError && caught.status === 410 && caught.code === "job_expired";
    } finally {
      if (mutation.current === pending) mutation.current = null;
      changing.current = false;
      if (mounted.current) setStage(null);
    }
  }

  return { job, stage, uploadBytes, error, expired, restoring, pollingPaused, start, cancel, clear, refresh,
    recoveryEnabled, setRecoveryEnabled, recoveryError, canRecover, recovered, recoveryPending };
}
