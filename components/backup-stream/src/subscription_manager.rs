// Copyright 2022 TiKV Project Authors. Licensed under Apache-2.0.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use crossbeam::channel::{Receiver as SyncReceiver, Sender as SyncSender};
use crossbeam_channel::SendError;
use engine_traits::KvEngine;
use error_code::{backup_stream::OBSERVE_CANCELED, ErrorCodeExt};
use futures::FutureExt;
use kvproto::metapb::Region;
use pd_client::PdClient;
use raft::StateRole;
use raftstore::{
    coprocessor::{ObserveHandle, RegionInfoProvider},
    router::RaftStoreRouter,
    store::fsm::ChangeObserver,
};
use tikv::storage::Statistics;
use tikv_util::{box_err, debug, info, time::Instant, warn, worker::Scheduler};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use txn_types::TimeStamp;
use yatp::task::callback::Handle as YatpHandle;

use crate::{
    annotate,
    endpoint::ObserveOp,
    errors::{Error, Result},
    event_loader::InitialDataLoader,
    future,
    metadata::{store::MetaStore, CheckpointProvider, MetadataClient},
    metrics,
    observer::BackupStreamObserver,
    router::Router,
    subscription_track::SubscriptionTracer,
    try_send,
    utils::{self, CallbackWaitGroup, Work},
    Task,
};

type ScanPool = yatp::ThreadPool<yatp::task::callback::TaskCell>;

/// a request for doing initial scanning.
struct ScanCmd {
    region: Region,
    handle: ObserveHandle,
    last_checkpoint: TimeStamp,
    work: Work,
}

/// The response of requesting resolve the new checkpoint of regions.
pub struct ResolvedRegions {
    items: Vec<(Region, TimeStamp)>,
    checkpoint: TimeStamp,
}

impl ResolvedRegions {
    /// compose the calculated global checkpoint and region checkpoints.
    /// note: maybe we can compute the global checkpoint internal and getting the interface clear.
    ///       however we must take the `min_ts` or we cannot provide valid global checkpoint if there
    ///       isn't any region checkpoint.
    pub fn new(checkpoint: TimeStamp, checkpoints: Vec<(Region, TimeStamp)>) -> Self {
        Self {
            items: checkpoints,
            checkpoint,
        }
    }

    /// take the region checkpoints from the structure.
    pub fn take_region_checkpoints(&mut self) -> Vec<(Region, TimeStamp)> {
        std::mem::take(&mut self.items)
    }

    /// get the global checkpoint.
    pub fn global_checkpoint(&self) -> TimeStamp {
        self.checkpoint
    }
}

/// the abstraction over a "DB" which provides the initial scanning.
trait InitialScan: Clone {
    fn do_initial_scan(
        &self,
        region: &Region,
        start_ts: TimeStamp,
        handle: ObserveHandle,
        on_finish: impl FnOnce() + Send + 'static,
    ) -> Result<Statistics>;
}

impl<E, R, RT> InitialScan for InitialDataLoader<E, R, RT>
where
    E: KvEngine,
    R: RegionInfoProvider + Clone + 'static,
    RT: RaftStoreRouter<E>,
{
    fn do_initial_scan(
        &self,
        region: &Region,
        start_ts: TimeStamp,
        handle: ObserveHandle,
        on_finish: impl FnOnce() + Send + 'static,
    ) -> Result<Statistics> {
        let region_id = region.get_id();
        let snap = self.observe_over_with_retry(region, move || {
            ChangeObserver::from_pitr(region_id, handle.clone())
        })?;
        let stat = self.do_initial_scan(region, start_ts, snap, on_finish)?;
        Ok(stat)
    }
}

impl ScanCmd {
    /// execute the initial scanning via the specificated [`InitialDataLoader`].
    fn exec_by(self, initial_scan: impl InitialScan) -> Result<()> {
        let Self {
            region,
            handle,
            last_checkpoint,
            work,
        } = self;
        let begin = Instant::now_coarse();
        let stat =
            initial_scan.do_initial_scan(&region, last_checkpoint, handle, move || drop(work))?;
        info!("initial scanning of leader transforming finished!"; "takes" => ?begin.saturating_elapsed(), "region" => %region.get_id(), "from_ts" => %last_checkpoint);
        utils::record_cf_stat("lock", &stat.lock);
        utils::record_cf_stat("write", &stat.write);
        utils::record_cf_stat("default", &stat.data);
        Ok(())
    }
}

fn scan_executor_loop(
    init: impl InitialScan,
    cmds: SyncReceiver<ScanCmd>,
    canceled: Arc<AtomicBool>,
) {
    while let Ok(cmd) = cmds.recv() {
        #[cfg(feature = "failpoints")]
        fail::fail_point!("execute_scan_command");
        debug!("handling initial scan request"; "region_id" => %cmd.region.get_id());
        metrics::PENDING_INITIAL_SCAN_LEN
            .with_label_values(&["queuing"])
            .dec();
        if canceled.load(Ordering::Acquire) {
            return;
        }
        metrics::PENDING_INITIAL_SCAN_LEN
            .with_label_values(&["executing"])
            .inc();
        let region_id = cmd.region.get_id();
        if let Err(err) = cmd.exec_by(init.clone()) {
            if err.error_code() != OBSERVE_CANCELED {
                err.report(format!("during initial scanning of region {}", region_id));
            }
        }
        metrics::PENDING_INITIAL_SCAN_LEN
            .with_label_values(&["executing"])
            .dec();
    }
}

/// spawn the executors in the scan pool.
/// we make workers thread instead of spawn scan task directly into the pool because the [`InitialDataLoader`] isn't `Sync` hence
/// we must use it very carefully or rustc (along with tokio) would complain that we made a `!Send` future.
/// so we have moved the data loader to the synchronous context so its reference won't be shared between threads any more.
fn spawn_executors(init: impl InitialScan + Send + 'static, number: usize) -> ScanPoolHandle {
    let (tx, rx) = crossbeam::channel::bounded(MESSAGE_BUFFER_SIZE);
    let pool = create_scan_pool(number);
    let stopped = Arc::new(AtomicBool::new(false));
    for _ in 0..number {
        let init = init.clone();
        let rx = rx.clone();
        let stopped = stopped.clone();
        pool.spawn(move |_: &mut YatpHandle<'_>| {
            tikv_alloc::add_thread_memory_accessor();
            let _io_guard = file_system::WithIOType::new(file_system::IOType::Replication);
            scan_executor_loop(init, rx, stopped);
            tikv_alloc::remove_thread_memory_accessor();
        })
    }
    ScanPoolHandle {
        tx,
        _pool: pool,
        stopped,
    }
}

struct ScanPoolHandle {
    tx: SyncSender<ScanCmd>,
    stopped: Arc<AtomicBool>,

    // in fact, we won't use the pool any more.
    // but we should hold the reference to the pool so it won't try to join the threads running.
    _pool: ScanPool,
}

impl Drop for ScanPoolHandle {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
    }
}

impl ScanPoolHandle {
    fn request(&self, cmd: ScanCmd) -> std::result::Result<(), SendError<ScanCmd>> {
        if self.stopped.load(Ordering::Acquire) {
            warn!("scan pool is stopped, ignore the scan command"; "region" => %cmd.region.get_id());
            return Ok(());
        }
        metrics::PENDING_INITIAL_SCAN_LEN
            .with_label_values(&["queuing"])
            .inc();
        self.tx.send(cmd)
    }
}

/// The default channel size.
const MESSAGE_BUFFER_SIZE: usize = 4096;

/// The operator for region subscription.
/// It make a queue for operations over the `SubscriptionTracer`, generally,
/// we should only modify the `SubscriptionTracer` itself (i.e. insert records, remove records) at here.
/// So the order subscription / desubscription won't be broken.
pub struct RegionSubscriptionManager<S, R, PDC> {
    // Note: these fields appear everywhere, maybe make them a `context` type?
    regions: R,
    meta_cli: MetadataClient<S>,
    pd_client: Arc<PDC>,
    range_router: Router,
    scheduler: Scheduler<Task>,
    observer: BackupStreamObserver,
    subs: SubscriptionTracer,

    messenger: Sender<ObserveOp>,
    scan_pool_handle: Arc<ScanPoolHandle>,
    scans: Arc<CallbackWaitGroup>,
}

impl<S, R, PDC> Clone for RegionSubscriptionManager<S, R, PDC>
where
    S: MetaStore + 'static,
    R: RegionInfoProvider + Clone + 'static,
    PDC: PdClient + 'static,
{
    fn clone(&self) -> Self {
        Self {
            regions: self.regions.clone(),
            meta_cli: self.meta_cli.clone(),
            // We should manually call Arc::clone here or rustc complains that `PDC` isn't `Clone`.
            pd_client: Arc::clone(&self.pd_client),
            range_router: self.range_router.clone(),
            scheduler: self.scheduler.clone(),
            observer: self.observer.clone(),
            subs: self.subs.clone(),
            messenger: self.messenger.clone(),
            scan_pool_handle: self.scan_pool_handle.clone(),
            scans: CallbackWaitGroup::new(),
        }
    }
}

/// Create a yatp pool for doing initial scanning.
fn create_scan_pool(num_threads: usize) -> ScanPool {
    yatp::Builder::new("log-backup-scan")
        .max_thread_count(num_threads)
        .build_callback_pool()
}

impl<S, R, PDC> RegionSubscriptionManager<S, R, PDC>
where
    S: MetaStore + 'static,
    R: RegionInfoProvider + Clone + 'static,
    PDC: PdClient + 'static,
{
    /// create a [`RegionSubscriptionManager`].
    ///
    /// # returns
    ///
    /// a two-tuple, the first is the handle to the manager, the second is the operator loop future.
    pub fn start<E, RT>(
        initial_loader: InitialDataLoader<E, R, RT>,
        observer: BackupStreamObserver,
        meta_cli: MetadataClient<S>,
        pd_client: Arc<PDC>,
        scan_pool_size: usize,
    ) -> (Self, future![()])
    where
        E: KvEngine,
        RT: RaftStoreRouter<E> + 'static,
    {
        let (tx, rx) = channel(MESSAGE_BUFFER_SIZE);
        let scan_pool_handle = spawn_executors(initial_loader.clone(), scan_pool_size);
        let op = Self {
            regions: initial_loader.regions.clone(),
            meta_cli,
            pd_client,
            range_router: initial_loader.sink.clone(),
            scheduler: initial_loader.scheduler.clone(),
            observer,
            subs: initial_loader.tracing,
            messenger: tx,
            scan_pool_handle: Arc::new(scan_pool_handle),
            scans: CallbackWaitGroup::new(),
        };
        let fut = op.clone().region_operator_loop(rx);
        (op, fut)
    }

    /// send an operation request to the manager.
    /// the returned future would be resolved after send is success.
    /// the opeartion would be executed asynchronously.
    pub async fn request(&self, op: ObserveOp) {
        if let Err(err) = self.messenger.send(op).await {
            annotate!(err, "BUG: region operator channel closed.")
                .report("when executing region op");
        }
    }

    /// wait initial scanning get finished.
    pub fn wait(&self, timeout: Duration) -> future![bool] {
        tokio::time::timeout(timeout, self.scans.wait()).map(|result| result.is_err())
    }

    /// the handler loop.
    async fn region_operator_loop(self, mut message_box: Receiver<ObserveOp>) {
        while let Some(op) = message_box.recv().await {
            info!("backup stream: on_modify_observe"; "op" => ?op);
            match op {
                ObserveOp::Start { region } => {
                    #[cfg(feature = "failpoints")]
                    fail::fail_point!("delay_on_start_observe");
                    self.start_observe(region).await;
                    metrics::INITIAL_SCAN_REASON
                        .with_label_values(&["leader-changed"])
                        .inc();
                    crate::observer::IN_FLIGHT_START_OBSERVE_MESSAGE.fetch_sub(1, Ordering::SeqCst);
                }
                ObserveOp::Stop { ref region } => {
                    self.subs.deregister_region_if(region, |_, _| true);
                }
                ObserveOp::Destroy { ref region } => {
                    let stopped = self.subs.deregister_region_if(region, |old, new| {
                        raftstore::store::util::compare_region_epoch(
                            old.meta.get_region_epoch(),
                            new,
                            true,
                            true,
                            false,
                        )
                        .map_err(|err| warn!("check epoch and stop failed."; "err" => %err))
                        .is_ok()
                    });
                    if stopped {
                        self.subs.destroy_stopped_region(region.get_id());
                    }
                }
                ObserveOp::RefreshResolver { ref region } => self.refresh_resolver(region).await,
                ObserveOp::NotifyFailToStartObserve {
                    region,
                    handle,
                    err,
                } => {
                    info!("retry observe region"; "region" => %region.get_id(), "err" => %err);
                    // No need for retrying observe canceled.
                    if err.error_code() == error_code::backup_stream::OBSERVE_CANCELED {
                        return;
                    }
                    match self.retry_observe(region, handle).await {
                        Ok(()) => {}
                        Err(e) => {
                            self.fatal(
                                e,
                                format!("While retring to observe region, origin error is {}", err),
                            );
                        }
                    }
                }
                ObserveOp::ResolveRegions { callback, min_ts } => {
                    let now = Instant::now();
                    let timedout = self.wait(Duration::from_secs(30)).await;
                    if timedout {
                        warn!("waiting for initial scanning done timed out, forcing progress(with risk of data loss)!"; 
                            "take" => ?now.saturating_elapsed(), "timedout" => %timedout);
                    }
                    let cps = self.subs.resolve_with(min_ts);
                    let min_region = cps.iter().min_by_key(|(_, rts)| rts);
                    // If there isn't any region observed, the `min_ts` can be used as resolved ts safely.
                    let rts = min_region.map(|(_, rts)| *rts).unwrap_or(min_ts);
                    info!("getting checkpoint"; "defined_by_region" => ?min_region.map(|r| r.0.get_id()), "checkpoint" => %rts);
                    self.subs.warn_if_gap_too_huge(rts);
                    callback(ResolvedRegions::new(rts, cps));
                }
            }
        }
    }

    fn fatal(&self, err: Error, message: String) {
        try_send!(self.scheduler, Task::FatalError(message, Box::new(err)));
    }

    async fn refresh_resolver(&self, region: &Region) {
        let need_refresh_all = !self.subs.try_update_region(region);

        if need_refresh_all {
            let canceled = self.subs.deregister_region_if(region, |_, _| true);
            let handle = ObserveHandle::new();
            if canceled {
                let for_task = self.find_task_by_region(region).unwrap_or_else(|| {
                    panic!(
                        "BUG: the region {:?} is register to no task but being observed",
                        region
                    )
                });
                metrics::INITIAL_SCAN_REASON
                    .with_label_values(&["region-changed"])
                    .inc();
                let r = async {
                    self.observe_over_with_initial_data_from_checkpoint(
                        region,
                        self.get_last_checkpoint_of(&for_task, region).await?,
                        handle.clone(),
                    );
                    Result::Ok(())
                }
                .await;
                if let Err(e) = r {
                    try_send!(
                        self.scheduler,
                        Task::ModifyObserve(ObserveOp::NotifyFailToStartObserve {
                            region: region.clone(),
                            handle,
                            err: Box::new(e)
                        })
                    );
                }
            }
        }
    }

    async fn try_start_observe(&self, region: &Region, handle: ObserveHandle) -> Result<()> {
        match self.find_task_by_region(region) {
            None => {
                warn!(
                    "the region {:?} is register to no task but being observed (start_key = {}; end_key = {}; task_stat = {:?}): maybe stale, aborting",
                    region,
                    utils::redact(&region.get_start_key()),
                    utils::redact(&region.get_end_key()),
                    self.range_router
                );
            }

            Some(for_task) => {
                #[cfg(feature = "failpoints")]
                fail::fail_point!("try_start_observe", |_| {
                    Err(Error::Other(box_err!("Nature is boring")))
                });
                let tso = self.get_last_checkpoint_of(&for_task, region).await?;
                self.observe_over_with_initial_data_from_checkpoint(region, tso, handle.clone());
            }
        }
        Ok(())
    }

    async fn start_observe(&self, region: Region) {
        let handle = ObserveHandle::new();
        if let Err(err) = self.try_start_observe(&region, handle.clone()).await {
            warn!("failed to start observe, retrying"; "err" => %err);
            try_send!(
                self.scheduler,
                Task::ModifyObserve(ObserveOp::NotifyFailToStartObserve {
                    region,
                    handle,
                    err: Box::new(err)
                })
            );
        }
    }

    async fn retry_observe(&self, region: Region, handle: ObserveHandle) -> Result<()> {
        let (tx, rx) = crossbeam::channel::bounded(1);
        self.regions
            .find_region_by_id(
                region.get_id(),
                Box::new(move |item| {
                    tx.send(item)
                        .expect("BUG: failed to send to newly created channel.");
                }),
            )
            .map_err(|err| {
                annotate!(
                    err,
                    "failed to send request to region info accessor, server maybe too too too busy. (region id = {})",
                    region.get_id()
                )
            })?;
        let new_region_info = rx
            .recv()
            .map_err(|err| annotate!(err, "BUG?: unexpected channel message dropped."))?;
        if new_region_info.is_none() {
            metrics::SKIP_RETRY
                .with_label_values(&["region-absent"])
                .inc();
            return Ok(());
        }
        let new_region_info = new_region_info.unwrap();
        if new_region_info.role != StateRole::Leader {
            metrics::SKIP_RETRY.with_label_values(&["not-leader"]).inc();
            return Ok(());
        }
        // Note: we may fail before we insert the region info to the subscription map.
        // At that time, the command isn't steal and we should retry it.
        let mut exists = false;
        let removed = self.subs.deregister_region_if(&region, |old, _| {
            exists = true;
            let should_remove = old.handle().id == handle.id;
            if !should_remove {
                warn!("stale retry command"; "region" => ?region, "handle" => ?handle, "old_handle" => ?old.handle());
            }
            should_remove
        });
        if !removed && exists {
            metrics::SKIP_RETRY
                .with_label_values(&["stale-command"])
                .inc();
            return Ok(());
        }
        metrics::INITIAL_SCAN_REASON
            .with_label_values(&["retry"])
            .inc();
        self.start_observe(region).await;
        Ok(())
    }

    async fn get_last_checkpoint_of(&self, task: &str, region: &Region) -> Result<TimeStamp> {
        let meta_cli = self.meta_cli.clone();
        let cp = meta_cli.get_region_checkpoint(task, region).await?;
        info!("got region checkpoint"; "region_id" => %region.get_id(), "checkpoint" => ?cp);
        if matches!(cp.provider, CheckpointProvider::Global) {
            metrics::STORE_CHECKPOINT_TS
                .with_label_values(&[task])
                .set(cp.ts.into_inner() as _);
        }
        Ok(cp.ts)
    }

    fn spawn_scan(&self, cmd: ScanCmd) {
        // we should not spawn initial scanning tasks to the tokio blocking pool
        // because it is also used for converting sync File I/O to async. (for now!)
        // In that condition, if we blocking for some resources(for example, the `MemoryQuota`)
        // at the block threads, we may meet some ghosty deadlock.
        let s = self.scan_pool_handle.request(cmd);
        if let Err(err) = s {
            let region_id = err.0.region.get_id();
            annotate!(err, "BUG: scan_pool closed")
                .report(format!("during initial scanning for region {}", region_id));
        }
    }

    fn observe_over_with_initial_data_from_checkpoint(
        &self,
        region: &Region,
        last_checkpoint: TimeStamp,
        handle: ObserveHandle,
    ) {
        self.subs
            .register_region(region, handle.clone(), Some(last_checkpoint));
        self.spawn_scan(ScanCmd {
            region: region.clone(),
            handle,
            last_checkpoint,
            work: self.scans.clone().work(),
        })
    }

    fn find_task_by_region(&self, r: &Region) -> Option<String> {
        self.range_router
            .find_task_by_range(&r.start_key, &r.end_key)
    }
}

#[cfg(test)]
mod test {
    use kvproto::metapb::Region;
    use tikv::storage::Statistics;

    use super::InitialScan;
    #[cfg(feature = "failpoints")]
    use crate::{subscription_manager::spawn_executors, utils::CallbackWaitGroup};

    #[derive(Clone, Copy)]
    struct NoopInitialScan;

    impl InitialScan for NoopInitialScan {
        fn do_initial_scan(
            &self,
            _region: &Region,
            _start_ts: txn_types::TimeStamp,
            _handle: raftstore::coprocessor::ObserveHandle,
            on_finish: impl FnOnce() + Send + 'static,
        ) -> crate::errors::Result<tikv::storage::Statistics> {
            on_finish();
            Ok(Statistics::default())
        }
    }

    #[cfg(feature = "failpoints")]
    fn should_finish_in(f: impl FnOnce() + Send + 'static, d: std::time::Duration) {
        let (tx, rx) = futures::channel::oneshot::channel();
        std::thread::spawn(move || {
            f();
            tx.send(()).unwrap();
        });
        let pool = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let _e = pool.handle().enter();
        pool.block_on(tokio::time::timeout(d, rx)).unwrap().unwrap();
    }

    #[test]
    #[cfg(feature = "failpoints")]
    fn test_message_delay_and_exit() {
        use std::time::Duration;

        use super::ScanCmd;

        let pool = spawn_executors(NoopInitialScan, 1);
        let wg = CallbackWaitGroup::new();
        fail::cfg("execute_scan_command", "sleep(100)").unwrap();
        for _ in 0..100 {
            let wg = wg.clone();
            pool.request(ScanCmd {
                region: Default::default(),
                handle: Default::default(),
                last_checkpoint: Default::default(),
                // Note: Maybe make here a Box<dyn FnOnce()> or some other trait?
                work: wg.work(),
            })
            .unwrap()
        }

        should_finish_in(move || drop(pool), Duration::from_secs(5));
    }
}
