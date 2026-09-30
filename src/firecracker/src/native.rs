// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone native mode. Main is the coordinator: it serves the API inline, with no API
//! thread, and owns the microVM's workers. A worker confined by the `vmm` filter runs the event
//! loop; the vCPU workers run the vCPUs. Both inherit main's `native_main` filter. Stopping
//! returns every worker's state to main, which can restart the same objects.

use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use micro_http::{Request, Response};
use vmm::builder::StartMicrovmError;
use vmm::logger::{error_unrestricted, info_unrestricted, warn_unrestricted};
use vmm::persist::{MicrovmState, MicrovmStateError, VmInfo};
use vmm::resources::{NativeProfileError, VmResources};
use vmm::rpc_interface::{
    PrebootApiController, RuntimeApiController, VmmAction, VmmActionError, VmmData,
};
use vmm::seccomp::{BpfProgram, BpfThreadMap};
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vstate::memory::GuestMemoryMmap;
use vmm::vstate::vcpu::Vcpu;
use vmm::vstate::vm::StartVcpusError;
use vmm::vstate::worker::{OwnedWorker, WorkerStartError};
use vmm::{EventManager, FcExitCode, Vmm, VmmError};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::api_server::parsed_request::{ParsedRequest, RequestAction};
use crate::api_server::{HttpServer, ServerError};

/// Errors of the native mode.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(crate) enum NativeError {
    /// Missing seccomp filter for thread category: {0}
    MissingFilter(&'static str),
    /// Cannot parse the configuration file: {0}
    Json(vmm::resources::ResourcesError),
    /// Cannot start the microVM: {0}
    Start(StartMicrovmError),
    /// Cannot resume the microVM: {0}
    Resume(VmmError),
    /// Cannot start the event worker: {0}
    Worker(WorkerStartError),
    /// Cannot start the vCPU workers: {0}
    Vcpus(StartVcpusError),
    /// Cannot serve the API: {0}
    Server(ServerError),
    /// The microVM stopped with an error: {0:?}
    Stopped(FcExitCode),
    /// Event descriptor failure: {0}
    EventFd(std::io::Error),
    /// Only a running microVM can be cloned
    NotRunning,
    /// Invalid clone request: {0}
    CloneRequest(String),
    /// Cannot capture the microVM: {0}
    Capture(MicrovmStateError),
    /// Cannot fork: {0}
    Fork(std::io::Error),
    /// The source cannot restart its microVM, which is lost: {0}
    SourceRestart(Box<NativeError>),
    /// Cannot give the child's root image its own description: {0}
    Root(std::io::Error),
    /// Cannot rebuild the child: {0}
    Restore(vmm::builder::BuildMicrovmFromSnapshotError),
    /// Cannot detach the interrupt lines before a capture: {0}
    IrqfdDetach(vmm::vstate::vm::VmError),
    /// The source cannot attach its interrupt lines again, and is lost: {0}
    IrqfdAttach(vmm::vstate::vm::VmError),
    /// The child could not get ready; the source runs on
    ChildFailed,
    /// The child's control connection failed: {0}
    Control(std::io::Error),
    /// The launcher cancelled the clone, or went away before committing it
    Cancelled,
    /// Cannot copy the scratch disk for the child: {0}
    Scratch(std::io::Error),
    /// Cannot lock the guest memory resident: {0}
    Residency(std::io::Error),
    /// The source could not run again, or died, before this child was published
    SourceLost,
    /// The microVM has shut down
    Exited,
    /// The source's outputs cannot be flushed before the fork: {0}
    SourceOutputs(String),
}

impl NativeError {
    /// Whether the process cannot go on serving after this error.
    fn is_fatal(&self) -> bool {
        matches!(
            self,
            NativeError::SourceRestart(_)
                | NativeError::IrqfdAttach(_)
                | NativeError::IrqfdDetach(vmm::vstate::vm::VmError::IrqfdRollback(..))
        )
    }
}

/// Asks the event worker to return its runtime to main.
#[derive(Debug)]
struct StopRequest {
    evt: EventFd,
    requested: bool,
}

impl MutEventSubscriber for StopRequest {
    fn process(&mut self, events: Events, _: &mut EventOps) {
        if events.event_set().contains(EventSet::IN) {
            // The counter only wakes the loop; `requested` carries the request.
            let _ = self.evt.read();
            self.requested = true;
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::new(&self.evt, EventSet::IN))
            .expect("Cannot register the native stop event");
    }
}

/// A clone child's control connection, watched only for the launcher closing it: the child's
/// microVM ends with its launcher, published or not. The data on it is main's to read.
#[derive(Debug)]
struct LauncherGone {
    control: std::os::unix::net::UnixStream,
    vmm: Arc<Mutex<Vmm>>,
}

impl MutEventSubscriber for LauncherGone {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        if events
            .event_set()
            .intersects(EventSet::HANG_UP | EventSet::READ_HANG_UP | EventSet::ERROR)
        {
            error_unrestricted!("The launcher went away; stopping the microVM.");
            let _ = ops.remove(Events::new(
                &self.control,
                EventSet::HANG_UP | EventSet::READ_HANG_UP,
            ));
            self.vmm.lock().unwrap().stop(FcExitCode::GenericError);
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // A launcher that shuts its side down for writing, or closes it, is gone.
        ops.add(Events::new(
            &self.control,
            EventSet::HANG_UP | EventSet::READ_HANG_UP,
        ))
        .expect("Cannot watch the launcher's control connection");
    }
}

/// What the event worker owns while it runs.
pub(crate) struct EventRuntime {
    event_manager: EventManager,
    vmm: Arc<Mutex<Vmm>>,
    stop: Arc<Mutex<StopRequest>>,
    /// Written when the microVM shuts down, to end main's API loop.
    exit_switch: Option<EventFd>,
    /// The configuration a captured state records.
    vm_info: VmInfo,
}

impl fmt::Debug for EventRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventRuntime")
            .field("vmm", &self.vmm)
            .field("stop", &self.stop)
            .finish_non_exhaustive()
    }
}

impl EventRuntime {
    fn new(
        mut event_manager: EventManager,
        vmm: Arc<Mutex<Vmm>>,
        exit_switch: Option<EventFd>,
        vm_info: VmInfo,
    ) -> Result<Self, NativeError> {
        let stop = Arc::new(Mutex::new(StopRequest {
            evt: EventFd::new(libc::EFD_NONBLOCK).map_err(NativeError::EventFd)?,
            requested: false,
        }));
        event_manager.add_subscriber(stop.clone());
        Ok(EventRuntime {
            event_manager,
            vmm,
            stop,
            exit_switch,
            vm_info,
        })
    }

    /// The event worker's loop: dispatches until the microVM's shutdown or a stop request.
    ///
    /// A shutdown is checked first: when it lands in the same dispatch as a stop request, main
    /// is still told the microVM exited, rather than finding it stopped and restarting it.
    fn serve(&mut self) {
        loop {
            self.event_manager
                .run()
                .expect("Failed to start the event manager");
            if self.vmm.lock().unwrap().shutdown_exit_code().is_some() {
                if let Some(exit_switch) = &self.exit_switch
                    && let Err(err) = exit_switch.write(1)
                {
                    error_unrestricted!("Cannot signal the microVM's exit: {err}");
                }
                return;
            }
            let mut stop = self.stop.lock().unwrap();
            if stop.requested {
                stop.requested = false;
                return;
            }
        }
    }
}

/// A running native microVM: its event worker and vCPU workers.
#[derive(Debug)]
pub(crate) struct NativeRuntime {
    worker: OwnedWorker<EventRuntime>,
    stop: Arc<Mutex<StopRequest>>,
    vmm: Arc<Mutex<Vmm>>,
    filters: RuntimeFilters,
}

/// The role filters the workers install on top of the inherited `native_main` filter.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeFilters {
    vmm: Arc<BpfProgram>,
    vcpu: Arc<BpfProgram>,
}

impl RuntimeFilters {
    pub(crate) fn new(filters: &BpfThreadMap) -> Result<Self, NativeError> {
        let get = |category: &'static str| {
            filters
                .get(category)
                .cloned()
                .ok_or(NativeError::MissingFilter(category))
        };
        Ok(RuntimeFilters {
            vmm: get("vmm")?,
            vcpu: get("vcpu")?,
        })
    }
}

/// A stopped native microVM: every worker joined, its state owned by main.
#[derive(Debug)]
pub(crate) struct StoppedRuntime {
    events: EventRuntime,
    vcpus: Vec<Vcpu>,
    running: bool,
    filters: RuntimeFilters,
}

impl NativeRuntime {
    /// Starts the event worker over a microVM whose vCPU workers already run.
    // The error hands the event runtime back; boxing it would only add an allocation.
    #[allow(clippy::result_large_err)]
    fn start(
        events: EventRuntime,
        filters: RuntimeFilters,
    ) -> Result<Self, (WorkerStartError, EventRuntime)> {
        let stop = events.stop.clone();
        let vmm = events.vmm.clone();
        #[cfg(test)]
        let vmm_filter = if tests::FAIL_EVENT_WORKER_START.replace(false) {
            // A filter the kernel refuses fails the start after the vCPU workers already run.
            Arc::new(vec![0; vmm::seccomp::BPF_MAX_LEN + 1])
        } else {
            filters.vmm.clone()
        };
        #[cfg(not(test))]
        let vmm_filter = filters.vmm.clone();
        let worker = OwnedWorker::start(
            thread::Builder::new().name("fc_native_vmm".to_owned()),
            events,
            vmm_filter,
            |_| {},
            EventRuntime::serve,
        )?;
        Ok(NativeRuntime {
            worker,
            stop,
            vmm,
            filters,
        })
    }

    /// Stops the vCPU workers, then the event worker, and returns what they owned.
    ///
    /// The vCPUs are the guest's producers: they stop first, all told to finish before any is
    /// joined, while the event worker still runs. Every queue notification a vCPU wrote before
    /// stopping is then pending on its ioeventfd, and the worker's last dispatch, which the stop
    /// request only ends after the descriptors ready alongside it, handles it. vCPU commands
    /// queued before the stop are handled by their vCPUs before those return.
    pub(crate) fn stop(self) -> StoppedRuntime {
        let (running, kvm_vm) = {
            let vmm = self.vmm.lock().unwrap();
            (
                vmm.instance_info.state == VmState::Running,
                vmm.vm.as_kvm().expect("native mode runs KVM").clone(),
            )
        };
        let vcpus = kvm_vm.stop_vcpus();
        self.stop
            .lock()
            .unwrap()
            .evt
            .write(1)
            .expect("Cannot request the event worker to stop");
        let events = self.worker.join();
        StoppedRuntime {
            events,
            vcpus,
            running,
            filters: self.filters,
        }
    }

    /// Waits for the microVM to shut down and its event worker to end.
    fn wait(self) -> Result<(), NativeError> {
        drop(self.worker.join());
        exit_result(&self.vmm)
    }
}

/// How the process ends for a microVM whose workers are done.
fn exit_result(vmm: &Mutex<Vmm>) -> Result<(), NativeError> {
    match vmm.lock().unwrap().shutdown_exit_code() {
        Some(FcExitCode::Ok) | None => Ok(()),
        Some(code) => Err(NativeError::Stopped(code)),
    }
}

impl StoppedRuntime {
    /// Captures the state of the stopped microVM and an owned clone of its guest memory, from
    /// which a fork child rebuilds: no worker runs, every pending vCPU exit completed before its
    /// thread returned, and the devices are saved before KVM, as a snapshot does.
    ///
    /// The line interrupts' IRQFDs are detached across the save: detaching completes any
    /// injection still in flight, so the saved interrupt controller holds every interrupt the
    /// stopped devices raised. Nothing is replayed from the devices' interrupt status. The same
    /// registrations are attached again before this returns, so the source restarts as it was.
    pub(crate) fn capture(&self) -> Result<(MicrovmState, GuestMemoryMmap), NativeError> {
        let mut vmm = self.events.vmm.lock().unwrap();
        let kvm_vm = vmm.vm.as_kvm().expect("native mode runs KVM").clone();
        kvm_vm.detach_irqfds().map_err(NativeError::IrqfdDetach)?;
        let state = vmm.save_stopped_state(&self.events.vm_info, &self.vcpus);
        kvm_vm.attach_irqfds().map_err(NativeError::IrqfdAttach)?;
        let state = state.map_err(NativeError::Capture)?;
        Ok((state, kvm_vm.guest_memory().clone()))
    }

    /// Restarts the original KVM, device and event objects in the state they were stopped in.
    /// On failure, every worker is stopped again and main keeps ownership.
    // The error hands the stopped runtime back; boxing it would only add an allocation.
    #[allow(clippy::result_large_err)]
    pub(crate) fn restart(self) -> Result<NativeRuntime, (NativeError, StoppedRuntime)> {
        let kvm_vm = self
            .events
            .vmm
            .lock()
            .unwrap()
            .vm
            .as_kvm()
            .expect("native mode runs KVM")
            .clone();
        let StoppedRuntime {
            events,
            vcpus,
            running,
            filters,
        } = self;
        if let Err((err, vcpus)) = kvm_vm.start_vcpus(vcpus, filters.vcpu.clone()) {
            let stopped = StoppedRuntime {
                events,
                vcpus,
                running,
                filters,
            };
            return Err((NativeError::Vcpus(err), stopped));
        }
        let runtime = match NativeRuntime::start(events, filters.clone()) {
            Ok(runtime) => runtime,
            Err((err, events)) => {
                let vcpus = kvm_vm.stop_vcpus();
                let stopped = StoppedRuntime {
                    events,
                    vcpus,
                    running,
                    filters,
                };
                return Err((NativeError::Worker(err), stopped));
            }
        };
        // The vCPU workers start paused.
        if running {
            let resumed = runtime.vmm.lock().unwrap().resume_vm();
            if let Err(err) = resumed {
                // Some vCPUs may have resumed; the intent to run survives the rollback.
                let mut stopped = runtime.stop();
                stopped.running = true;
                return Err((NativeError::Resume(err), stopped));
            }
        }
        Ok(runtime)
    }
}

/// Builds the configured microVM and starts every worker, confined and ready, before the guest
/// runs.
fn boot(
    instance_info: &InstanceInfo,
    resources: &VmResources,
    mut event_manager: EventManager,
    filters: &BpfThreadMap,
    runtime_filters: &RuntimeFilters,
    exit_switch: Option<EventFd>,
) -> Result<NativeRuntime, NativeError> {
    let vmm =
        vmm::builder::build_and_boot_microvm(instance_info, resources, &mut event_manager, filters)
            .map_err(NativeError::Start)?;
    // The guest memory was mapped after startup locked the process's working set.
    lock_resident()?;
    let events = EventRuntime::new(
        event_manager,
        vmm.clone(),
        exit_switch,
        VmInfo::from(resources),
    )?;
    let runtime = NativeRuntime::start(events, runtime_filters.clone())
        .map_err(|(err, _)| NativeError::Worker(err))?;
    let resumed = vmm.lock().unwrap().resume_vm();
    if let Err(err) = resumed {
        drop(runtime.stop());
        return Err(NativeError::Resume(err));
    }
    info_unrestricted!("Started native microVM");
    Ok(runtime)
}

/// Rejects requests outside the native profile before anything is built from them.
fn admit(action: &VmmAction) -> Result<(), VmmActionError> {
    let unsupported = |what: &str| {
        Err(VmmActionError::NotSupported(format!(
            "{what} is not supported in native mode"
        )))
    };
    match action {
        VmmAction::LoadSnapshot(_) => unsupported("loading a snapshot"),
        VmmAction::InsertNetworkDevice(_) | VmmAction::UpdateNetworkInterface(_) => {
            unsupported("networking")
        }
        VmmAction::SetVsockDevice(_) => unsupported("vsock"),
        VmmAction::SetEntropyDevice(_) => unsupported("the entropy device"),
        VmmAction::InsertBlockDevice(config) => NativeProfileError::check_drive(config)
            .map_err(|err| VmmActionError::NotSupported(err.to_string())),
        VmmAction::UpdateBlockDevice(update) if update.rate_limiter.is_some() => {
            unsupported("a drive rate limiter")
        }
        VmmAction::ConfigureSerial(serial) if serial.rate_limiter.is_some() => {
            unsupported("a serial rate limiter")
        }
        _ => Ok(()),
    }
}

/// Main's microVM: configured, then running under its workers.
// Main holds the only instance for the process's lifetime; boxing would only add an allocation.
#[allow(clippy::large_enum_variant)]
enum Phase {
    Preboot {
        resources: VmResources,
        event_manager: EventManager,
    },
    Running {
        runtime: NativeRuntime,
        controller: RuntimeApiController,
    },
    /// Startup failed; the process exits once the failing request is answered.
    Failed,
    /// The guest shut down while its workers stopped for a clone: it neither restarts nor
    /// clones, and the process exits as for any shutdown.
    Exited(StoppedRuntime),
}

/// Main's coordinator: owns the microVM through every phase and handles each request inline.
struct Coordinator<'a> {
    filters: &'a BpfThreadMap,
    runtime_filters: RuntimeFilters,
    instance_info: InstanceInfo,
    exit_switch: Option<EventFd>,
    phase: Phase,
    fatal: Option<NativeError>,
}

impl<'a> Coordinator<'a> {
    fn new(
        filters: &'a BpfThreadMap,
        instance_info: InstanceInfo,
        mut resources: VmResources,
        exit_switch: Option<EventFd>,
    ) -> Result<Self, NativeError> {
        resources.native = true;
        Ok(Coordinator {
            filters,
            runtime_filters: RuntimeFilters::new(filters)?,
            instance_info,
            exit_switch,
            phase: Phase::Preboot {
                resources,
                event_manager: EventManager::new().expect("Unable to create EventManager"),
            },
            fatal: None,
        })
    }

    /// Boots the configured microVM; a failure is fatal.
    fn start(&mut self) -> Result<(), NativeError> {
        let Phase::Preboot {
            resources,
            event_manager,
        } = std::mem::replace(&mut self.phase, Phase::Failed)
        else {
            unreachable!("only a configured microVM starts");
        };
        let exit_switch = match &self.exit_switch {
            Some(switch) => Some(switch.try_clone().map_err(NativeError::EventFd)?),
            None => None,
        };
        let runtime = boot(
            &self.instance_info,
            &resources,
            event_manager,
            self.filters,
            &self.runtime_filters,
            exit_switch,
        )?;
        self.phase = Phase::Running {
            controller: RuntimeApiController::new(runtime.vmm.clone()),
            runtime,
        };
        Ok(())
    }

    /// Handles one request. `InstanceStart` is acknowledged only once every worker is ready and
    /// the guest runs, and the next request, even pipelined, reaches the running microVM.
    fn handle(&mut self, action: VmmAction) -> Result<VmmData, VmmActionError> {
        admit(&action)?;
        if matches!(action, VmmAction::StartMicroVm) && matches!(self.phase, Phase::Preboot { .. })
        {
            return match self.start() {
                Ok(()) => Ok(VmmData::Empty),
                Err(err) => {
                    let response = Err(VmmActionError::NotSupported(err.to_string()));
                    self.fatal = Some(err);
                    response
                }
            };
        }
        match &mut self.phase {
            Phase::Preboot {
                resources,
                event_manager,
            } => PrebootApiController::new(
                self.filters,
                self.instance_info.clone(),
                resources,
                event_manager,
            )
            .handle_preboot_request(action),
            Phase::Running { controller, .. } => controller.handle_request(action),
            Phase::Failed | Phase::Exited(_) => Err(VmmActionError::OperationNotSupportedPostBoot),
        }
    }

    /// Clones the running microVM. Every worker stops and is joined, leaving main as the only
    /// thread; the state and an owned clone of guest memory are captured; then main forks. The
    /// source restarts its original objects in their prior Running or Paused state; the child
    /// returns what it rebuilds from. A source that cannot restart is lost, and says so.
    fn clone_vm(&mut self, http: &Request) -> Result<CloneRole, NativeError> {
        let request: CloneRequest = http
            .body
            .as_ref()
            .ok_or_else(|| NativeError::CloneRequest("missing body".to_string()))
            .and_then(|body| {
                serde_json::from_slice(body.raw())
                    .map_err(|err| NativeError::CloneRequest(err.to_string()))
            })?;
        let Phase::Running { runtime, .. } = &self.phase else {
            return Err(NativeError::NotRunning);
        };
        // A guest that already shut down is never cloned; main exits once it sees the shutdown.
        if runtime.vmm.lock().unwrap().shutdown_exit_code().is_some() {
            return Err(NativeError::Exited);
        }
        // The child's scratch disk is a reflinked copy, taken once every writer stopped.
        let config = runtime.vmm.lock().unwrap().full_config();
        let has_scratch = config.drives.iter().any(|drive| !drive.is_root_device);
        if has_scratch != request.scratch_path.is_some() {
            return Err(NativeError::CloneRequest(
                "scratch_path must be given exactly when the microVM has a scratch drive"
                    .to_string(),
            ));
        }
        let Phase::Running {
            runtime,
            controller,
        } = std::mem::replace(&mut self.phase, Phase::Failed)
        else {
            unreachable!("checked above");
        };
        let stopped = runtime.stop();
        // The guest shut down as its workers stopped: the event worker, which saw the shutdown
        // last, told main to exit, and the stopped microVM is kept only until then.
        if stopped
            .events
            .vmm
            .lock()
            .unwrap()
            .shutdown_exit_code()
            .is_some()
        {
            self.phase = Phase::Exited(stopped);
            return Err(NativeError::Exited);
        }
        let (state, memory) = match stopped.capture() {
            Ok(captured) => captured,
            // A source whose interrupt lines cannot be attached again must not run on.
            Err(err) if err.is_fatal() => return Err(err),
            Err(err) => {
                self.resume_source(stopped, controller)?;
                return Err(err);
            }
        };
        let machine_config = stopped.events.vmm.lock().unwrap().machine_config.clone();
        if let Err(err) = flush_source_outputs() {
            self.resume_source(stopped, controller)?;
            return Err(err);
        }
        // Everything that can fail before the fork restores the source and leaves no new path.
        let prepared = request
            .scratch_path
            .as_deref()
            .map(ScratchCopy::reflink)
            .transpose()
            .map_err(NativeError::Scratch)
            .and_then(|scratch| {
                let pipes = readiness_pipe()
                    .and_then(|ready| Ok((ready, readiness_pipe()?)))
                    .map_err(NativeError::Fork);
                match pipes {
                    Ok(pipes) => Ok((scratch, pipes)),
                    Err(err) => {
                        if let Some(scratch) = scratch {
                            scratch.abandon();
                        }
                        Err(err)
                    }
                }
            });
        let (scratch, ((ready_rx, ready_tx), (recovered_rx, recovered_tx))) = match prepared {
            Ok(prepared) => prepared,
            Err(err) => {
                self.resume_source(stopped, controller)?;
                return Err(err);
            }
        };
        // SAFETY: `stop` joined every worker, so main is this process's only thread and the child
        // starts with no lock held and no other thread's state half-copied.
        #[cfg(test)]
        let fork = if tests::FAIL_CLONE.get() == Some(tests::CloneFailure::Fork) {
            tests::FAIL_CLONE.set(None);
            // SAFETY: setting errno as a failed fork would.
            unsafe { *libc::__errno_location() = libc::EAGAIN };
            -1
        } else {
            // SAFETY: as below.
            unsafe { libc::fork() }
        };
        #[cfg(not(test))]
        // SAFETY: as above.
        let fork = unsafe { libc::fork() };
        match fork {
            -1 => {
                let err = std::io::Error::last_os_error();
                if let Some(scratch) = scratch {
                    scratch.abandon();
                }
                self.resume_source(stopped, controller)?;
                Err(NativeError::Fork(err))
            }
            0 => {
                drop(ready_rx);
                drop(recovered_tx);
                Ok(CloneRole::Child(Box::new(ChildSeed {
                    inherited: stopped,
                    inherited_controller: controller,
                    instance_info: self.instance_info.clone(),
                    machine_config,
                    state,
                    memory,
                    request,
                    ready: ready_tx,
                    recovered: recovered_rx,
                    scratch: scratch.map(|copy| copy.fd),
                })))
            }
            pid => {
                drop(ready_tx);
                drop(recovered_rx);
                drop(scratch);
                drop(memory);
                // A source that cannot restart is lost; the child sees the acknowledgment
                // pipe close unwritten and exits unpublished.
                self.resume_source(stopped, controller)?;
                std::io::Write::write_all(&mut std::fs::File::from(recovered_tx), &[1])
                    .map_err(|_| NativeError::ChildFailed)?;
                // The clone succeeds only once the child is ready too; it closes the pipe
                // unwritten, by exiting, if it cannot rebuild.
                let mut byte = [0u8; 1];
                match std::io::Read::read(&mut std::fs::File::from(ready_rx), &mut byte) {
                    Ok(1) => Ok(CloneRole::Source(pid)),
                    _ => Err(NativeError::ChildFailed),
                }
            }
        }
    }

    /// Restarts the source's original runtime, or declares it lost.
    fn resume_source(
        &mut self,
        stopped: StoppedRuntime,
        controller: RuntimeApiController,
    ) -> Result<(), NativeError> {
        match stopped.restart() {
            Ok(runtime) => {
                self.phase = Phase::Running {
                    runtime,
                    controller,
                };
                Ok(())
            }
            Err((err, _stopped)) => Err(NativeError::SourceRestart(Box::new(err))),
        }
    }

    fn wait(self) -> Result<(), NativeError> {
        match self.phase {
            Phase::Running { runtime, .. } => runtime.wait(),
            Phase::Exited(stopped) => exit_result(&stopped.events.vmm),
            _ => Ok(()),
        }
    }
}

/// Builds and runs a native microVM from a JSON configuration, without an API.
pub(crate) fn run_json(
    filters: &BpfThreadMap,
    config_json: &str,
    instance_info: InstanceInfo,
    boot_timer: bool,
) -> Result<(), NativeError> {
    let mut resources = VmResources::from_native_json(config_json).map_err(NativeError::Json)?;
    resources.boot_timer = boot_timer;
    let mut coordinator = Coordinator::new(filters, instance_info, resources, None)?;
    coordinator.start()?;
    coordinator.wait()
}

/// Answers one parsed API request through `handle`, as the API thread would.
fn respond(
    request: &Request,
    handle: &mut dyn FnMut(VmmAction) -> Result<VmmData, VmmActionError>,
) -> Response {
    match ParsedRequest::try_from(request).map(|parsed| parsed.into_parts()) {
        Ok((action, mut parsing_info)) => {
            let mut response = match action {
                RequestAction::Sync(action) => ParsedRequest::convert_to_response(&handle(*action)),
                RequestAction::Immediate(data) => ParsedRequest::convert_to_response(&Ok(*data)),
            };
            if let Some(message) = parsing_info.take_deprecation_message() {
                warn_unrestricted!("{}", message);
                response.set_deprecation();
            }
            response
        }
        Err(err) => {
            error_unrestricted!("{:?}", err);
            err.into()
        }
    }
}

/// Binds the API socket, ended by `exit_switch`, which the event worker writes when the
/// microVM exits.
fn bind_api(
    path: &PathBuf,
    payload_limit: usize,
    exit_switch: &EventFd,
) -> Result<HttpServer, NativeError> {
    let mut server = HttpServer::new(path).map_err(NativeError::Server)?;
    server.set_payload_max_size(payload_limit);
    server
        .add_kill_switch(exit_switch.try_clone().map_err(NativeError::EventFd)?)
        .map_err(NativeError::Server)?;
    Ok(server)
}

/// Serves the API inline on main, starting from an optional JSON configuration: requests are
/// answered one at a time, each against the phase the previous one left. A clone's child
/// leaves the source's server unanswered and serves its own.
pub(crate) fn run_api(
    filters: &BpfThreadMap,
    config_json: Option<&str>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    boot_timer: bool,
    api_payload_limit: usize,
) -> Result<(), NativeError> {
    let exit_switch = EventFd::new(libc::EFD_NONBLOCK).map_err(NativeError::EventFd)?;
    let mut server = bind_api(&bind_path, api_payload_limit, &exit_switch)?;
    let resources = match config_json {
        Some(json) => VmResources::from_native_json(json).map_err(NativeError::Json)?,
        None => VmResources::default(),
    };
    let mut coordinator = Coordinator::new(
        filters,
        instance_info,
        VmResources {
            boot_timer,
            ..resources
        },
        Some(exit_switch),
    )?;
    if config_json.is_some() {
        coordinator.start()?;
    }

    server.start_server().map_err(NativeError::Server)?;
    info_unrestricted!("Listening on API socket ({bind_path:?}) in native mode.");
    loop {
        match serve(&mut server, &mut coordinator)? {
            Served::Exited => return coordinator.wait(),
            Served::Child(seed) => {
                // The source's server, connections and pending requests close unanswered.
                drop(server);
                drop(coordinator);
                let (child_server, child) = match seed.become_child(filters, api_payload_limit) {
                    Ok(child) => child,
                    Err(failure) => {
                        if let ChildFailure::After(err) = failure {
                            error_unrestricted!("The clone's child failed: {err}");
                        }
                        // Nothing in this process unwinds into its source's outputs: the stderr
                        // it inherited is its source's, and so are its logger and metrics
                        // until it took its own. The source sees the readiness pipe close.
                        // SAFETY: ending this process without running its teardown.
                        unsafe { libc::_exit(1) }
                    }
                };
                server = child_server;
                coordinator = child;
            }
        }
    }
}

/// How serving the API ended.
enum Served {
    /// The microVM exited.
    Exited,
    /// This process is a clone's child.
    Child(Box<ChildSeed>),
}

/// Serves requests until the microVM exits or this process becomes a clone's child.
fn serve(
    server: &mut HttpServer,
    coordinator: &mut Coordinator<'_>,
) -> Result<Served, NativeError> {
    loop {
        let requests = match server.requests() {
            Ok(requests) => requests,
            Err(ServerError::ShutdownEvent) => {
                server.flush_outgoing_writes();
                return Ok(Served::Exited);
            }
            Err(err) => {
                error_unrestricted!("API Server error on retrieving incoming request: {}", err);
                continue;
            }
        };
        for request in requests {
            let response = if is_clone_request(request.inner()) {
                match coordinator.clone_vm(request.inner()) {
                    Ok(CloneRole::Source(pid)) => crate::api_server::ApiServer::json_response(
                        micro_http::StatusCode::OK,
                        format!(r#"{{"child_pid":{pid}}}"#),
                    ),
                    // The child answers nothing on the source's connection.
                    Ok(CloneRole::Child(seed)) => return Ok(Served::Child(seed)),
                    Err(err) => {
                        let response = ParsedRequest::convert_to_response(&Err(
                            VmmActionError::NotSupported(err.to_string()),
                        ));
                        if err.is_fatal() {
                            coordinator.fatal = Some(err);
                        }
                        response
                    }
                }
            } else {
                let mut handle = |action| coordinator.handle(action);
                respond(request.inner(), &mut handle)
            };
            let mut response = Some(response);
            let response = request.process(|_| response.take().unwrap());
            if let Err(err) = server.respond(response) {
                error_unrestricted!("API Server encountered an error on response: {}", err);
            }
            if let Some(err) = coordinator.fatal.take() {
                // Deliver the failing request's response before exiting.
                server.flush_outgoing_writes();
                return Err(err);
            }
        }
    }
}

/// `PUT /clone`, native mode's own request.
fn is_clone_request(request: &Request) -> bool {
    request.method() == micro_http::Method::Put && request.uri().get_abs_path() == "/clone"
}

/// Body of `PUT /clone`. Every destination is the child's own: its API socket, the launcher's
/// control socket it connects to, its identity, and where it logs, counts and writes its
/// console.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CloneRequest {
    api_sock: PathBuf,
    control_sock: PathBuf,
    instance_id: String,
    log_path: PathBuf,
    metrics_path: PathBuf,
    serial_out_path: PathBuf,
    /// Where the child's copy of the scratch disk is created, when the microVM has one.
    scratch_path: Option<PathBuf>,
}

/// Leaves nothing buffered that a child could write into its source's outputs: the source's
/// metrics are written, which empties their line writer, and the process's buffered stdout,
/// where the logger writes without a log path, is flushed, partial line included. If either
/// fails, the clone is refused.
fn flush_source_outputs() -> Result<(), NativeError> {
    vmm::logger::METRICS
        .write()
        .map_err(|err| NativeError::SourceOutputs(format!("metrics: {err}")))?;
    std::io::Write::flush(&mut std::io::stdout())
        .map_err(|err| NativeError::SourceOutputs(format!("stdout: {err}")))
}

/// The child's scratch disk: a file this clone created, a reflinked copy of the stopped
/// source's scratch disk, opened as the jailer hands the scratch disk over: read-write and
/// `O_DIRECT`.
struct ScratchCopy {
    fd: std::os::fd::OwnedFd,
    path: PathBuf,
}

impl ScratchCopy {
    /// Creates `path`, which must not exist, as the copy; on failure no new path remains.
    fn reflink(path: &std::path::Path) -> Result<Self, std::io::Error> {
        use std::os::unix::fs::OpenOptionsExt;

        let copy = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_DIRECT)
            .open(path)?;
        let copy = ScratchCopy {
            fd: copy.into(),
            path: path.to_path_buf(),
        };
        // SAFETY: both descriptors are open; FICLONE only reads the source's extents.
        let cloned = unsafe {
            libc::ioctl(
                std::os::fd::AsRawFd::as_raw_fd(&copy.fd),
                libc::FICLONE,
                vmm::devices::virtio::block::SCRATCH_DESCRIPTOR_FILENO,
            )
        };
        if cloned < 0 {
            let err = std::io::Error::last_os_error();
            copy.abandon();
            return Err(err);
        }
        Ok(copy)
    }

    /// Removes the copy this clone created, when the clone fails before its child exists.
    fn abandon(self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            error_unrestricted!("Cannot remove the abandoned scratch copy: {err}");
        }
    }
}

/// Longest record the launcher's control connection carries.
const VERDICT_MAX: usize = 16;

/// Reads the launcher's verdict, one newline-terminated record however the stream splits it.
/// Only `commit` publishes; `cancel`, any other or overlong record, and the connection ending
/// do not.
fn read_verdict(control: &mut impl std::io::Read) -> Result<bool, std::io::Error> {
    let mut record = Vec::with_capacity(VERDICT_MAX);
    let mut byte = [0u8; 1];
    while record.len() < VERDICT_MAX {
        match control.read(&mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) if byte[0] == b'\n' => return Ok(record == b"commit"),
            Ok(_) => record.push(byte[0]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    Ok(false)
}

/// Locks every current mapping, guest memory included, faulting pages in only when touched:
/// `MCL_CURRENT` covers only what is mapped when it runs, and locks are not inherited.
fn lock_resident() -> Result<(), NativeError> {
    // SAFETY: `mlockall` only changes this process's own memory policy.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_ONFAULT) } < 0 {
        return Err(NativeError::Residency(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// A pipe the child writes one byte to once it is ready; both ends close on exec and fork
/// hands each branch its own.
fn readiness_pipe() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd), std::io::Error> {
    #[cfg(test)]
    if tests::FAIL_CLONE.get() == Some(tests::CloneFailure::Pipe) {
        tests::FAIL_CLONE.set(None);
        return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
    }
    let mut fds = [-1; 2];
    // SAFETY: `fds` has room for both ends, and the result is checked.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned by nothing else.
    unsafe {
        Ok((
            std::os::fd::FromRawFd::from_raw_fd(fds[0]),
            std::os::fd::FromRawFd::from_raw_fd(fds[1]),
        ))
    }
}

/// Which side of a clone's fork this process is.
enum CloneRole {
    /// The source, running its original objects again; the child has this pid.
    Source(libc::pid_t),
    /// The child, holding what it inherited and what it rebuilds from.
    Child(Box<ChildSeed>),
}

/// How a clone's child failed to become one.
enum ChildFailure {
    /// Before its outputs were its own, so it must not report anything.
    BeforeOutputs,
    /// After, so its own log reports it.
    After(NativeError),
}

/// What a clone's child starts from: the inherited, stopped source runtime and controller,
/// which it disposes of, and the captured state and adopted guest memory it rebuilds from.
struct ChildSeed {
    inherited: StoppedRuntime,
    inherited_controller: RuntimeApiController,
    instance_info: InstanceInfo,
    machine_config: vmm::vmm_config::machine_config::MachineConfig,
    state: MicrovmState,
    memory: GuestMemoryMmap,
    request: CloneRequest,
    ready: std::os::fd::OwnedFd,
    /// Written once by the source when it runs its original objects again.
    recovered: std::os::fd::OwnedFd,
    scratch: Option<std::os::fd::OwnedFd>,
}

impl ChildSeed {
    /// Marks the inherited graph, so no failure can drop it normally, then takes the child's
    /// own identity and output destinations before anything else can fail: until they are its
    /// own, every destination the child holds is its source's, so a failure there is
    /// [`ChildFailure::BeforeOutputs`] and the child writes nothing about it.
    fn become_child(
        self,
        filters: &BpfThreadMap,
        api_payload_limit: usize,
    ) -> Result<(HttpServer, Coordinator<'_>), ChildFailure> {
        self.inherited.events.vmm.lock().unwrap().mark_inherited();
        vmm::logger::set_instance_id(self.request.instance_id.clone());
        let outputs_taken = vmm::logger::LOGGER.redirect(&self.request.log_path).is_ok()
            && vmm::vmm_config::metrics::rebind_metrics(vmm::vmm_config::metrics::MetricsConfig {
                metrics_path: self.request.metrics_path.clone(),
            })
            .is_ok();
        if !outputs_taken {
            return Err(ChildFailure::BeforeOutputs);
        }
        self.rebuild(filters, api_payload_limit)
            .map_err(ChildFailure::After)
    }

    /// Disposes of the inherited graph without touching the source's objects, gives the root
    /// image its own open file description, and rebuilds a fresh microVM, paused, over the
    /// adopted guest memory, locked again.
    ///
    /// It then reports ready to the source and to the launcher's control connection, and waits
    /// there for the launcher: `commit` publishes it, serving its API, where Resume starts the
    /// guest; `cancel`, or the connection closing because the launcher died, ends it without the
    /// guest ever running.
    fn rebuild(
        self,
        filters: &BpfThreadMap,
        api_payload_limit: usize,
    ) -> Result<(HttpServer, Coordinator<'_>), NativeError> {
        let ChildSeed {
            inherited,
            inherited_controller,
            mut instance_info,
            machine_config,
            state,
            memory,
            request,
            ready,
            recovered,
            scratch,
        } = self;
        instance_info.id = request.instance_id.clone();
        // The description `GET /` reports is process-global and still the source's: the child
        // publishes its own. The state it reports is published separately, Paused by the rebuild.
        instance_info.publish();
        // A duplicate shares the source's file offset, which the sync block engine seeks.
        let root = std::fs::File::open(format!(
            "/proc/self/fd/{}",
            vmm::devices::virtio::block::ROOT_DESCRIPTOR_FILENO
        ))
        .map_err(NativeError::Root)?;
        drop(inherited_controller);
        drop(inherited);
        let root = std::os::fd::IntoRawFd::into_raw_fd(root);
        // SAFETY: `root` is owned here; slot 4 holds the inherited, unowned root descriptor,
        // which the child replaces with its own description of the same image.
        unsafe {
            if libc::dup2(root, vmm::devices::virtio::block::ROOT_DESCRIPTOR_FILENO) < 0
                || libc::close(root) < 0
            {
                return Err(NativeError::Root(std::io::Error::last_os_error()));
            }
        }
        if let Some(scratch) = scratch {
            let scratch = std::os::fd::IntoRawFd::into_raw_fd(scratch);
            // SAFETY: `scratch` is owned here; slot 5 holds the inherited, unowned scratch
            // descriptor, which the child replaces with its reflinked copy.
            unsafe {
                if libc::dup2(
                    scratch,
                    vmm::devices::virtio::block::SCRATCH_DESCRIPTOR_FILENO,
                ) < 0
                    || libc::close(scratch) < 0
                {
                    return Err(NativeError::Scratch(std::io::Error::last_os_error()));
                }
            }
        }

        let mut resources = VmResources {
            machine_config,
            serial_out_path: Some(request.serial_out_path),
            native: true,
            ..Default::default()
        };
        let mut event_manager = EventManager::new().expect("Unable to create EventManager");
        #[cfg(test)]
        let filters = if tests::FAIL_CHILD_RESTORE.replace(false) {
            // A filter map the restore cannot take a vCPU filter from fails it.
            &*tests::NO_FILTERS
        } else {
            filters
        };
        let vmm = vmm::builder::build_native_microvm_from_state(
            &instance_info,
            &mut event_manager,
            state,
            memory,
            filters,
            &mut resources,
        )
        .map_err(NativeError::Restore)?;
        // Memory locks are not inherited across the fork.
        lock_resident()?;
        // The child's own control connection; the event loop watches it for the launcher going
        // away, which ends this microVM, before and after commit alike.
        let mut control = std::os::unix::net::UnixStream::connect(&request.control_sock)
            .map_err(NativeError::Control)?;
        event_manager.add_subscriber(Arc::new(Mutex::new(LauncherGone {
            control: control.try_clone().map_err(NativeError::Control)?,
            vmm: vmm.clone(),
        })));
        let exit_switch = EventFd::new(libc::EFD_NONBLOCK).map_err(NativeError::EventFd)?;
        let events = EventRuntime::new(
            event_manager,
            vmm.clone(),
            Some(exit_switch.try_clone().map_err(NativeError::EventFd)?),
            VmInfo::from(&resources),
        )?;
        let runtime = NativeRuntime::start(events, RuntimeFilters::new(filters)?)
            .map_err(|(err, _)| NativeError::Worker(err))?;

        // Ready: the launcher learns it on the child's own control connection, the source
        // through the pipe only this child holds the writing end of.
        std::io::Write::write_all(&mut control, b"ready\n").map_err(NativeError::Control)?;
        std::io::Write::write_all(&mut std::fs::File::from(ready), &[1])
            .map_err(NativeError::Control)?;
        // Publication needs the source recovered as well as a commit, in either order: an
        // early commit waits unread. A source that could not restart, or died before saying
        // so, closes this pipe unwritten, and the unpublished child exits.
        let mut byte = [0u8; 1];
        if !matches!(
            std::io::Read::read(&mut std::fs::File::from(recovered), &mut byte),
            Ok(1)
        ) {
            return Err(NativeError::SourceLost);
        }
        if !read_verdict(&mut control).map_err(NativeError::Control)? {
            // Cancelled, or the launcher is gone: the unpublished guest never runs.
            return Err(NativeError::Cancelled);
        }

        let mut server = bind_api(&request.api_sock, api_payload_limit, &exit_switch)?;
        server.start_server().map_err(NativeError::Server)?;
        let coordinator = Coordinator {
            filters,
            runtime_filters: RuntimeFilters::new(filters)?,
            instance_info,
            exit_switch: Some(exit_switch),
            phase: Phase::Running {
                controller: RuntimeApiController::new(vmm),
                runtime,
            },
            fatal: None,
        };
        Ok((server, coordinator))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::*;

    /// The launcher's verdict is read under the embedded `native_main` filter, as a clone
    /// child reads it (through the socket's `recvfrom`). A system call the filter lacks kills
    /// the forked reader with SIGSYS. With the empty debug filters this only exercises the
    /// sequence; run it against the release build: `cargo test --release --target
    /// x86_64-unknown-linux-musl -p firecracker --bin firecracker --
    /// native::tests::test_read_verdict_under_embedded_filters`.
    #[test]
    fn test_read_verdict_under_embedded_filters() {
        use std::os::unix::net::UnixStream;

        let filters = crate::seccomp::get_filters(crate::seccomp::SeccompConfig::Advanced).unwrap();
        let native_main = crate::seccomp::native_main_filter(&filters).unwrap();
        let (mut launcher, mut child) = UnixStream::pair().unwrap();
        launcher.write_all(b"commit\n").unwrap();
        // SAFETY: the child only installs the filter, reads the verdict and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let committed = vmm::seccomp::apply_filter(&native_main).is_ok()
                && matches!(read_verdict(&mut child), Ok(true));
            // SAFETY: ending the forked child without the harness's teardown.
            unsafe { libc::_exit(if committed { 0 } else { 1 }) }
        }
        let mut status = 0;
        // SAFETY: waiting for the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "read_verdict under native_main: status {status:#x}"
        );
    }

    /// A commit split across writes publishes once; cancel, another record, an overlong record,
    /// a record cut off by the connection closing and a half-close do not.
    #[test]
    fn test_read_verdict_takes_only_a_whole_commit_record() {
        use std::os::unix::net::UnixStream;

        let verdict = |writes: &[&[u8]], half_close: bool| {
            let (mut launcher, mut child) = UnixStream::pair().unwrap();
            let writes: Vec<Vec<u8>> = writes.iter().map(|write| write.to_vec()).collect();
            let writer = std::thread::spawn(move || {
                for write in writes {
                    launcher.write_all(&write).unwrap();
                    std::thread::sleep(Duration::from_millis(20));
                }
                if half_close {
                    launcher.shutdown(std::net::Shutdown::Write).unwrap();
                    std::thread::sleep(Duration::from_millis(50));
                }
            });
            let verdict = read_verdict(&mut child).unwrap();
            writer.join().unwrap();
            verdict
        };
        assert!(verdict(&[b"co", b"mmit\n"], false));
        assert!(verdict(&[b"commit\ncancel\n"], false));
        assert!(!verdict(&[b"cancel\n"], false));
        assert!(!verdict(&[b"commitx\n"], false));
        assert!(!verdict(&[b"commitcommitcommit\n"], false));
        assert!(!verdict(&[b"commit"], false));
        assert!(!verdict(&[b"com"], true));
    }

    /// Runs `check` on a forked copy of this process whose descriptor 1 is the writing end of a
    /// pipe, whose reading end, unless `reader_open`, is closed everywhere first, after the
    /// child wrote `partial` through the process's stdout with no newline, so its line buffer
    /// keeps it. Returns the child's exit code and what reached the pipe.
    fn with_buffered_partial_stdout(reader_open: bool, check: fn() -> bool) -> (i32, Vec<u8>) {
        let mut pipe = [-1; 2];
        // SAFETY: `pipe` has room for both descriptors.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        if !reader_open {
            // SAFETY: closing the reading end created above; nothing else holds it.
            assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
        }
        // SAFETY: the child only rearranges descriptors, writes, checks and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: descriptor calls on the pipe created above, then the child's exit.
            unsafe {
                libc::dup2(pipe[1], libc::STDOUT_FILENO);
                libc::close(pipe[1]);
                let buffered = std::io::stdout().write_all(b"partial").is_ok();
                // Nothing reached the pipe yet: the line writer holds the partial line.
                let mut pending = 0;
                let held = !reader_open
                    || libc::ioctl(pipe[0], libc::FIONREAD, &mut pending) == 0 && pending == 0;
                libc::_exit(if !buffered || !held {
                    2
                } else if check() {
                    0
                } else {
                    1
                });
            }
        }
        // SAFETY: closing this side's writing end, so the read below ends with the child.
        unsafe { libc::close(pipe[1]) };
        let mut status = 0;
        // SAFETY: waiting for the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "{status:#x}");
        let mut written = Vec::new();
        if reader_open {
            // SAFETY: taking ownership of the reading end created above.
            let mut reader = unsafe { File::from_raw_fd(pipe[0]) };
            reader.read_to_end(&mut written).unwrap();
        }
        (libc::WEXITSTATUS(status), written)
    }

    /// The clone's preparation flushes a partial line the source's stdout buffered, so no child
    /// inherits it; the flush is `std::io::stdout`'s, which keeps its line buffering otherwise.
    #[test]
    fn test_source_outputs_flush_a_partial_stdout_line() {
        let (code, written) = with_buffered_partial_stdout(true, || flush_source_outputs().is_ok());
        assert_eq!(code, 0);
        assert_eq!(written, b"partial");
    }

    /// A stdout that cannot take the source's buffered partial line refuses the clone.
    #[test]
    fn test_source_outputs_refuse_the_clone_when_stdout_cannot_flush() {
        let (code, _) = with_buffered_partial_stdout(
            false,
            || matches!(flush_source_outputs(), Err(NativeError::SourceOutputs(err)) if err.starts_with("stdout")),
        );
        assert_eq!(code, 0);
    }

    /// A scratch copy whose reflink fails leaves no new path behind, and a path that already
    /// exists is never taken over or removed.
    #[test]
    fn test_scratch_copy_failure_leaves_no_new_path() {
        let dir = std::env::temp_dir().join(format!("native-scratch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Descriptor 5 is no reflinkable scratch disk in this test process.
        let fresh = dir.join("fresh");
        ScratchCopy::reflink(&fresh).err().unwrap();
        assert!(!fresh.exists());

        let existing = dir.join("existing");
        std::fs::write(&existing, b"someone else's").unwrap();
        let err = ScratchCopy::reflink(&existing).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&existing).unwrap(), b"someone else's");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Scratch copies are reflinks of the scratch disk at descriptor 5, taken by the product's
    /// `ScratchCopy::reflink`: after two copies, the source and a child writing the same sector,
    /// and the child another one, leave each file with only its own writes and the sibling copy
    /// with the disk as it was at the clone.
    ///
    /// `NATIVE_REFLINK_DIR=<dir on a reflink-capable filesystem> cargo test -p firecracker --bin
    /// firecracker -- --ignored --exact native::tests::test_scratch_copies_are_independent_reflinks`
    #[test]
    #[ignore = "needs NATIVE_REFLINK_DIR on a reflink-capable filesystem; takes descriptor 5"]
    fn test_scratch_copies_are_independent_reflinks() {
        use std::os::unix::fs::FileExt;

        const SECTOR: usize = 4096;
        let dir = PathBuf::from(
            std::env::var_os("NATIVE_REFLINK_DIR").expect("NATIVE_REFLINK_DIR is not set"),
        )
        .join(format!("native-reflink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at_clone: Vec<u8> = (0..2 * SECTOR)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        std::fs::write(dir.join("source"), &at_clone).unwrap();
        let source = File::options()
            .read(true)
            .write(true)
            .open(dir.join("source"))
            .unwrap();
        // Whatever the harness keeps at descriptor 5 is set aside and put back afterwards.
        // SAFETY: duplicating a descriptor number, and taking slot 5 for the source's disk.
        let saved = unsafe { libc::fcntl(5, libc::F_DUPFD_CLOEXEC, 10) };
        // SAFETY: as above.
        assert_eq!(unsafe { libc::dup2(source.as_raw_fd(), 5) }, 5);
        let copies = ScratchCopy::reflink(&dir.join("child"))
            .and_then(|child| Ok((child, ScratchCopy::reflink(&dir.join("sibling"))?)));
        // SAFETY: putting back, or releasing, slot 5.
        unsafe {
            if saved >= 0 {
                assert_eq!(libc::dup2(saved, 5), 5);
                assert_eq!(libc::close(saved), 0);
            } else {
                assert_eq!(libc::close(5), 0);
            }
        }
        drop(copies.unwrap());

        // The copies are open O_DIRECT; buffered descriptors write the same files.
        let open = |name: &str| {
            File::options()
                .read(true)
                .write(true)
                .open(dir.join(name))
                .unwrap()
        };
        source.write_all_at(&[b'S'; SECTOR], 0).unwrap();
        let child = open("child");
        child.write_all_at(&[b'C'; SECTOR], 0).unwrap();
        child.write_all_at(&[b'D'; SECTOR], SECTOR as u64).unwrap();
        for file in [&source, &child] {
            file.sync_all().unwrap();
        }

        let read = |name: &str| std::fs::read(dir.join(name)).unwrap();
        assert_eq!(read("source")[..SECTOR], [b'S'; SECTOR]);
        assert_eq!(read("source")[SECTOR..], at_clone[SECTOR..]);
        assert_eq!(read("child")[..SECTOR], [b'C'; SECTOR]);
        assert_eq!(read("child")[SECTOR..], [b'D'; SECTOR]);
        assert_eq!(read("sibling"), at_clone);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn guest_dir() -> PathBuf {
        std::env::var_os("NATIVE_GUEST_DIR").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/native-qualification-guest"),
            PathBuf::from,
        )
    }

    /// A fixture file: the name `var` gives, or `default`, in [`guest_dir`].
    fn guest_file(var: &str, default: &str) -> PathBuf {
        guest_dir().join(std::env::var_os(var).map_or_else(|| default.into(), PathBuf::from))
    }

    const SEALS: i32 =
        libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

    /// Installs the fixture root image, sealed in a memfd, as a read-only description at
    /// descriptor 4, which nothing in this process owns afterwards: the block builder takes it.
    fn install_sealed_root(image: &Path) {
        // SAFETY: probing whether a descriptor number is open.
        assert!(
            unsafe { libc::fcntl(4, libc::F_GETFD) } < 0,
            "descriptor 4 is in use"
        );
        // SAFETY: the name is a valid C string; the result is checked.
        let fd = unsafe {
            libc::memfd_create(
                c"native-root".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0, "{}", std::io::Error::last_os_error());
        // SAFETY: `fd` is a fresh descriptor owned by nothing else.
        let mut memfd = unsafe { File::from_raw_fd(fd) };
        memfd.write_all(&std::fs::read(image).unwrap()).unwrap();
        // SAFETY: adding seals to an owned memfd.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) }, 0);
        let root = File::open(format!("/proc/self/fd/{fd}")).unwrap();
        // The memfd may hold slot 4 itself; its owner closes it before slot 4 is filled.
        drop(memfd);
        let root = root.into_raw_fd();
        if root != 4 {
            // SAFETY: slot 4 is free, and `root` is the raw descriptor this function owns.
            unsafe {
                assert_eq!(libc::dup2(root, 4), 4);
                assert_eq!(libc::close(root), 0);
            }
        }
    }

    /// Fills free slots below 4 with placeholders, leaving `free_below` of them free.
    fn occupy_slots_below_4(free_below: usize) -> Vec<File> {
        let mut placeholders = Vec::new();
        loop {
            let placeholder = File::open("/dev/null").unwrap();
            if placeholder.as_raw_fd() >= 4 {
                break;
            }
            placeholders.push(placeholder);
        }
        placeholders.truncate(placeholders.len().saturating_sub(free_below));
        placeholders
    }

    /// Slot 4 ends up holding the sealed read-only root whether the memfd itself (no free slot
    /// below 4) or the read-only reopening (one free slot below 4) first landed on 4.
    ///
    /// It changes this process's descriptor table, so run it alone:
    /// `cargo test -p firecracker --bin firecracker -- --ignored --exact
    /// native::tests::test_install_sealed_root_owns_slot_4`.
    #[test]
    #[ignore = "rearranges process descriptors; run alone"]
    fn test_install_sealed_root_owns_slot_4() {
        let image = std::env::temp_dir().join(format!("native-root-{}.img", std::process::id()));
        std::fs::write(&image, b"asymmetric root image").unwrap();
        for free_below in [0, 1] {
            let placeholders = occupy_slots_below_4(free_below);
            if free_below == 1 && placeholders.is_empty() {
                // Every slot below 4 is the harness's; the reopening cannot land on 4.
                continue;
            }
            install_sealed_root(&image);
            drop(placeholders);
            // SAFETY: reading flags and seals of descriptor 4, which the setup handed over.
            unsafe {
                assert_eq!(
                    libc::fcntl(4, libc::F_GETFL) & libc::O_ACCMODE,
                    libc::O_RDONLY
                );
                assert_eq!(libc::fcntl(4, libc::F_GET_SEALS) & SEALS, SEALS);
            }
            let mut contents = String::new();
            // SAFETY: descriptor 4 is open, owned by nothing else; this File closes it.
            unsafe { File::from_raw_fd(4) }
                .read_to_string(&mut contents)
                .unwrap();
            assert_eq!(contents, "asymmetric root image");
            // SAFETY: probing whether a descriptor number is open.
            assert!(unsafe { libc::fcntl(4, libc::F_GETFD) } < 0);
        }
        std::fs::remove_file(image).unwrap();
    }

    fn last_heartbeat(serial: &Path) -> Option<u64> {
        std::fs::read_to_string(serial)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_once("NATIVE_HEARTBEAT tick="))
            .filter_map(|(_, rest)| rest.split_whitespace().next()?.parse().ok())
            .next_back()
    }

    fn wait_for_heartbeat_after(serial: &Path, after: u64) -> u64 {
        let start = Instant::now();
        loop {
            if let Some(tick) = last_heartbeat(serial).filter(|tick| *tick > after) {
                return tick;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "no heartbeat after {after}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    static EMPTY_FILTERS: std::sync::LazyLock<BpfThreadMap> =
        std::sync::LazyLock::new(vmm::seccomp::get_empty_filters);

    /// Boots the fixture guest, its console to `serial`, through the native coordinator.
    fn boot_fixture(serial: &Path) -> Coordinator<'static> {
        install_sealed_root(&guest_file("NATIVE_GUEST_ROOTFS", "rootfs.squashfs"));
        let _ = std::fs::remove_file(serial);
        let config = format!(
            r#"{{
                "boot-source": {{
                    "kernel_image_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=squashfs init=/init"
                }},
                "machine-config": {{"vcpu_count": 2, "mem_size_mib": 128}},
                "drives": [{{"drive_id": "rootfs", "is_root_device": true, "is_read_only": true, "fd": 4, "io_engine": "Sync"}}]
            }}"#,
            guest_file("NATIVE_GUEST_KERNEL", "vmlinux-6.1.155")
                .canonicalize()
                .unwrap()
                .display()
        );
        let mut resources = VmResources::from_native_json(&config).unwrap();
        resources.serial_out_path = Some(serial.to_path_buf());
        let mut coordinator =
            Coordinator::new(&EMPTY_FILTERS, InstanceInfo::default(), resources, None).unwrap();
        coordinator.start().unwrap();
        coordinator
    }

    /// A clone whose readiness pipes or fork fail restarts the source, which runs on, answers
    /// again, and can still clone.
    ///
    /// `cargo test -p firecracker --bin firecracker -- --ignored --exact
    /// native::tests::test_clone_failure_before_fork_restores_the_source`, with `/dev/kvm` and
    /// `NATIVE_GUEST_DIR` naming the fixture.
    #[test]
    #[ignore = "needs /dev/kvm and the native guest fixture"]
    fn test_clone_failure_before_fork_restores_the_source() {
        let serial =
            std::env::temp_dir().join(format!("native-rollback-{}.log", std::process::id()));
        let mut coordinator = boot_fixture(&serial);
        let mut tick = wait_for_heartbeat_after(&serial, 0);
        let body = r#"{"api_sock":"c.sock","control_sock":"l.sock","instance_id":"c","log_path":"c.log","metrics_path":"c.metrics","serial_out_path":"c.serial"}"#;
        let raw = format!(
            "PUT /clone HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = Request::try_from(raw.as_bytes(), None).unwrap();
        for failure in [CloneFailure::Pipe, CloneFailure::Fork] {
            FAIL_CLONE.set(Some(failure));
            let err = coordinator.clone_vm(&request).err().unwrap();
            assert!(!err.is_fatal(), "{err}");
            assert!(matches!(err, NativeError::Fork(_)), "{err}");
            assert!(matches!(coordinator.phase, Phase::Running { .. }));
            tick = wait_for_heartbeat_after(&serial, tick);
        }
    }

    /// The source's restart fails right after the fork while the launcher commits the child
    /// early: the source is lost, and the child, committed but never told its source recovered,
    /// exits without serving its API. The child is this forked test process; which of its
    /// waits sees the source gone first (the ready pipe or the recovered pipe) is a race, and
    /// either way it must end unpublished.
    ///
    /// `cargo test -p firecracker --bin firecracker -- --ignored --exact
    /// native::tests::test_early_commit_child_exits_when_its_source_cannot_restart`, with
    /// `/dev/kvm` and `NATIVE_GUEST_DIR` naming the fixture.
    #[test]
    #[ignore = "needs /dev/kvm and the native guest fixture"]
    fn test_early_commit_child_exits_when_its_source_cannot_restart() {
        let dir = std::env::temp_dir().join(format!("native-early-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let serial = dir.join("source.serial");
        let mut coordinator = boot_fixture(&serial);
        wait_for_heartbeat_after(&serial, 0);
        let listener = std::os::unix::net::UnixListener::bind(dir.join("control.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let at = |name: &str| dir.join(name).display().to_string();
        let body = format!(
            r#"{{"api_sock":"{}","control_sock":"{}","instance_id":"early","log_path":"{}","metrics_path":"{}","serial_out_path":"{}"}}"#,
            at("child.sock"),
            at("control.sock"),
            at("child.log"),
            at("child.metrics"),
            at("child.serial")
        );
        let raw = format!(
            "PUT /clone HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = Request::try_from(raw.as_bytes(), None).unwrap();

        FAIL_EVENT_WORKER_START.set(true);
        match coordinator.clone_vm(&request) {
            Ok(CloneRole::Child(seed)) => {
                // The hook was meant for the source's restart only.
                FAIL_EVENT_WORKER_START.set(false);
                let code = match seed.become_child(&EMPTY_FILTERS, 4096) {
                    Err(ChildFailure::After(NativeError::SourceLost)) => 0,
                    Err(ChildFailure::After(NativeError::Control(_))) => 0,
                    Err(ChildFailure::After(_)) => 2,
                    Err(ChildFailure::BeforeOutputs) => 3,
                    Ok(_) => 4,
                };
                // SAFETY: ending the forked child without the harness's teardown.
                unsafe { libc::_exit(code) }
            }
            Ok(CloneRole::Source(_)) => panic!("the source recovered"),
            Err(err) => {
                assert!(matches!(err, NativeError::SourceRestart(_)), "{err}");
                assert!(err.is_fatal());
            }
        }
        // The launcher commits as soon as the child connects.
        let start = Instant::now();
        let mut control = loop {
            match listener.accept() {
                Ok((control, _)) => break Some(control),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > Duration::from_secs(10) {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("{err}"),
            }
        };
        if let Some(control) = control.as_mut() {
            let _ = control.write_all(b"commit\n");
        }
        let mut status = 0;
        // SAFETY: waiting for the clone child this test forked, its only child.
        assert!(unsafe { libc::waitpid(-1, &mut status, 0) } > 0);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child: status {status:#x}"
        );
        assert!(!dir.join("child.sock").exists());
        assert!(last_heartbeat(&dir.join("child.serial")).is_none());
    }

    /// A child whose restore fails, after it took its own outputs and disposed of what it
    /// inherited but before it is ready, fails with the typed restore error: it never connects
    /// to the launcher, serves nothing and runs no guest, and exits; its source, told the child
    /// failed, keeps running, and so does its guest. This drives the seed directly, not
    /// `run_api`, which reports a child's failure; the fixture integration test covers that.
    ///
    /// `cargo test -p firecracker --bin firecracker -- --ignored --exact
    /// native::tests::test_child_restore_failure_before_ready_keeps_the_source`, with
    /// `/dev/kvm` and `NATIVE_GUEST_DIR` naming the fixture.
    #[test]
    #[ignore = "needs /dev/kvm and the native guest fixture"]
    fn test_child_restore_failure_before_ready_keeps_the_source() {
        let dir = std::env::temp_dir().join(format!("native-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let serial = dir.join("source.serial");
        let mut coordinator = boot_fixture(&serial);
        let tick = wait_for_heartbeat_after(&serial, 0);
        let listener = std::os::unix::net::UnixListener::bind(dir.join("control.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let at = |name: &str| dir.join(name).display().to_string();
        let body = format!(
            r#"{{"api_sock":"{}","control_sock":"{}","instance_id":"restore","log_path":"{}","metrics_path":"{}","serial_out_path":"{}"}}"#,
            at("child.sock"),
            at("control.sock"),
            at("child.log"),
            at("child.metrics"),
            at("child.serial")
        );
        let raw = format!(
            "PUT /clone HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let request = Request::try_from(raw.as_bytes(), None).unwrap();

        // Only the child reaches a restore, so only its copy of the hook fires.
        FAIL_CHILD_RESTORE.set(true);
        let result = coordinator.clone_vm(&request);
        if let Ok(CloneRole::Child(seed)) = result {
            let code = match seed.become_child(&EMPTY_FILTERS, 4096) {
                Err(ChildFailure::After(NativeError::Restore(_))) => 0,
                Err(ChildFailure::After(_)) => 2,
                Err(ChildFailure::BeforeOutputs) => 3,
                Ok(_) => 4,
            };
            // SAFETY: ending the forked child without the harness's teardown.
            unsafe { libc::_exit(code) }
        }
        FAIL_CHILD_RESTORE.set(false);
        let err = result.err().expect("the clone succeeded");
        assert!(matches!(err, NativeError::ChildFailed), "{err}");
        assert!(!err.is_fatal());
        assert!(matches!(coordinator.phase, Phase::Running { .. }));
        let mut status = 0;
        // SAFETY: reaping the clone child this test forked, its only child.
        assert!(unsafe { libc::waitpid(-1, &mut status, 0) } > 0);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child: status {status:#x}"
        );

        // The source's guest runs on; the child left no endpoint and ran no guest.
        wait_for_heartbeat_after(&serial, tick);
        assert!(!dir.join("child.sock").exists());
        assert!(matches!(
            listener.accept(),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
        ));
        assert!(last_heartbeat(&dir.join("child.serial")).is_none());
        // `become_child` reports nothing itself: `run_api`, bypassed here, logs its failure.
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A clone child's disposal with the production objects: the stopped runtime (its VMM and
    /// block graph marked inherited) is dropped in a forked process that keeps the captured
    /// memory collection. The child must neither write the console nor lose the retained guest
    /// memory; its source then restarts the same objects, and the guest runs on, so disposal
    /// changed none of the source's event loop, KVM objects or devices. The harness process's
    /// other threads make this fork no substitute for the product's sole-thread boundary.
    #[test]
    #[ignore = "needs /dev/kvm and the native guest fixture"]
    fn test_inherited_disposal_leaves_the_source_running() {
        use vmm::vstate::memory::{Bytes, GuestAddress};

        let serial =
            std::env::temp_dir().join(format!("native-disposal-{}.log", std::process::id()));
        let coordinator = boot_fixture(&serial);
        let Phase::Running { runtime, .. } = coordinator.phase else {
            panic!("the microVM did not start");
        };
        let before_stop = wait_for_heartbeat_after(&serial, 0);
        let stopped = runtime.stop();
        let (_state, memory) = stopped.capture().unwrap();
        let console_len = std::fs::metadata(&serial).unwrap().len();
        let byte: u8 = memory.read_obj(GuestAddress(0x100000)).unwrap();

        // SAFETY: the child only drops what it inherited, inspects and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let check = |ok: bool, code: i32| {
                if !ok {
                    // SAFETY: ending the forked child without the harness's teardown.
                    unsafe { libc::_exit(code) }
                }
            };
            stopped.events.vmm.lock().unwrap().mark_inherited();
            drop(stopped);
            check(
                std::fs::metadata(&serial).map(|m| m.len()).ok() == Some(console_len),
                10,
            );
            check(
                memory.read_obj::<u8>(GuestAddress(0x100000)).ok() == Some(byte),
                11,
            );
            // The root image slot stays open for the child's own description of it.
            // SAFETY: probing a descriptor number.
            check(unsafe { libc::fcntl(4, libc::F_GETFD) } >= 0, 12);
            // SAFETY: as above.
            unsafe { libc::_exit(0) }
        }
        let mut status = 0;
        // SAFETY: waiting for the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "disposal: status {status:#x}"
        );
        drop(memory);
        let runtime = stopped.restart().map_err(|(err, _)| err).unwrap();
        let stopped_at = last_heartbeat(&serial).unwrap();
        assert!(stopped_at >= before_stop);
        wait_for_heartbeat_after(&serial, stopped_at);
        drop(runtime.stop());
    }

    /// Stops a booted guest through the production boundary and restarts its original objects:
    /// no worker runs while stopped, the same VMM restarts Running, and the guest continues.
    ///
    /// `cargo test -p firecracker --bin firecracker -- --ignored --exact
    /// native::tests::test_native_runtime_stop_restart_continues_guest`, with `/dev/kvm` and
    /// `NATIVE_GUEST_DIR` naming the fixture.
    #[test]
    #[ignore = "needs /dev/kvm and the native guest fixture"]
    fn test_native_runtime_stop_restart_continues_guest() {
        let serial =
            std::env::temp_dir().join(format!("native-restart-{}.log", std::process::id()));
        let coordinator = boot_fixture(&serial);
        let Phase::Running { runtime, .. } = coordinator.phase else {
            panic!("the microVM did not start");
        };
        let before_stop = wait_for_heartbeat_after(&serial, 0);

        let vmm = runtime.vmm.clone();
        let kvm_vm = vmm.lock().unwrap().vm.as_kvm().unwrap().clone();
        let stopped = runtime.stop();
        assert_eq!(stopped.vcpus.len(), 2);
        assert!(stopped.running);
        assert!(kvm_vm.vcpus_handles().is_empty());
        // The capture a fork child rebuilds from: both vCPUs, and the memory registered with KVM.
        let (state, memory) = stopped.capture().unwrap();
        assert_eq!(state.vcpu_states.len(), 2);
        assert_eq!(
            state.vm_state.memory,
            vmm::vstate::memory::GuestMemoryExtension::describe(&memory)
        );
        drop(memory);
        // Heartbeats come every second; none arrives while every vCPU is stopped.
        let stopped_at = last_heartbeat(&serial).unwrap();
        assert!(stopped_at >= before_stop);
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(last_heartbeat(&serial), Some(stopped_at));

        // The event worker fails to start after the vCPU workers ran: everything is stopped again
        // and returned, the Running intent intact, and the same objects restart from it.
        FAIL_EVENT_WORKER_START.set(true);
        let (err, stopped) = stopped.restart().unwrap_err();
        assert!(matches!(
            err,
            NativeError::Worker(WorkerStartError::Filter(_))
        ));
        assert_eq!(stopped.vcpus.len(), 2);
        assert!(stopped.running);
        assert!(kvm_vm.vcpus_handles().is_empty());

        let runtime = stopped.restart().map_err(|(err, _)| err).unwrap();
        assert!(Arc::ptr_eq(&runtime.vmm, &vmm));
        assert_eq!(kvm_vm.vcpus_handles().len(), 2);
        assert_eq!(vmm.lock().unwrap().instance_info.state, VmState::Running);
        let resumed_at = wait_for_heartbeat_after(&serial, stopped_at);

        // A paused microVM stops and restarts paused: no heartbeat until it is resumed.
        vmm.lock().unwrap().pause_vm().unwrap();
        let stopped = runtime.stop();
        assert!(!stopped.running);
        let runtime = stopped.restart().map_err(|(err, _)| err).unwrap();
        assert_eq!(vmm.lock().unwrap().instance_info.state, VmState::Paused);
        let paused_at = last_heartbeat(&serial).unwrap();
        assert!(paused_at >= resumed_at);
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(last_heartbeat(&serial), Some(paused_at));
        vmm.lock().unwrap().resume_vm().unwrap();
        wait_for_heartbeat_after(&serial, paused_at);

        let stopped = runtime.stop();
        assert_eq!(stopped.vcpus.len(), 2);
    }

    thread_local! {
        /// Whether the next event worker start fails.
        pub(super) static FAIL_EVENT_WORKER_START: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
        /// Which step between capture and fork the next clone fails at.
        pub(super) static FAIL_CLONE: std::cell::Cell<Option<CloneFailure>> =
            const { std::cell::Cell::new(None) };
        /// Whether the next clone child's restore fails.
        pub(super) static FAIL_CHILD_RESTORE: std::cell::Cell<bool> =
            const { std::cell::Cell::new(false) };
    }

    /// A filter map without the vCPU filter a child's restore needs.
    pub(super) static NO_FILTERS: std::sync::LazyLock<BpfThreadMap> =
        std::sync::LazyLock::new(BpfThreadMap::new);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum CloneFailure {
        Pipe,
        Fork,
    }
}
