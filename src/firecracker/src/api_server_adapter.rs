// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm::logger::{ProcessTimeReporter, error_unrestricted, info_unrestricted, warn_unrestricted};
use vmm::rpc_interface::{
    ApiRequest, ApiRequestChannels, ApiResponse, BuildMicrovmFromRequestsError,
    PrebootApiController, RuntimeApiController, VmmAction,
};
use vmm::seccomp::BpfThreadMap;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::{EventManager, FcExitCode, Vmm};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::api_server::{ApiServer, HttpServer, ServerError};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ApiServerError {
    /// Failed to build MicroVM: {0}.
    BuildMicroVmError(BuildMicrovmFromRequestsError),
    /// MicroVM stopped with an error: {0:?}
    MicroVMStoppedWithError(FcExitCode),
    /// Failed to open the API socket at: {0}. Check that it is not already used.
    FailedToBindSocket(String),
    /// Failed to bind and run the HTTP server: {0}
    FailedToBindAndRunHttpServer(ServerError),
    /// Failed to build MicroVM from Json: {0}
    BuildFromJson(crate::BuildFromJsonError),
}

#[derive(Debug)]
struct ApiServerAdapter {
    api_event_fd: EventFd,
    from_api: Receiver<ApiRequest>,
    to_api: Sender<ApiResponse>,
    controller: RuntimeApiController,
    request: Option<ApiRequest>,
}

impl ApiServerAdapter {
    /// Runs the vmm to completion, while any arising control events are deferred
    /// to a `RuntimeApiController`.
    fn run_microvm(
        api_event_fd: EventFd,
        from_api: Receiver<ApiRequest>,
        to_api: Sender<ApiResponse>,
        vmm: Arc<Mutex<Vmm>>,
        event_manager: &mut EventManager,
    ) -> Result<(), ApiServerError> {
        let api_adapter = Arc::new(Mutex::new(Self {
            api_event_fd,
            from_api,
            to_api,
            controller: RuntimeApiController::new(vmm.clone()),
            request: None,
        }));
        event_manager.add_subscriber(api_adapter.clone());
        loop {
            vmm::vstate::farplane::dispatch_slice(event_manager)
                .expect("EventManager events driver fatal error");
            api_adapter.lock().expect("Poisoned lock").handle_request();

            match vmm.lock().unwrap().shutdown_exit_code() {
                Some(FcExitCode::Ok) => break,
                Some(exit_code) => return Err(ApiServerError::MicroVMStoppedWithError(exit_code)),
                None => continue,
            }
        }
        Ok(())
    }

    fn handle_request(&mut self) {
        let staged = self.request.take();
        let controller = &mut self.controller;
        serve_actions(staged, &self.from_api, &self.to_api, |action| {
            Box::new(controller.handle_request(action))
        });
    }
}

/// Serves one staged API action and, if it paused the microVM, every action up to the resume.
///
/// Each action executes inside `outside_capture_epoch`: an action staged before a capture epoch
/// closed the dispatch gate reaches the microVM only once the epoch ends, so it cannot mutate VM
/// or device state between the vmstate and the dirty harvest of the same checkpoint.
///
/// The hold is taken per action and never across the blocking receive of the paused mode: an
/// adapter waiting for the next action would otherwise keep a capture from starting at all.
fn serve_actions(
    staged: Option<ApiRequest>,
    from_api: &Receiver<ApiRequest>,
    to_api: &Sender<ApiResponse>,
    mut execute: impl FnMut(VmmAction) -> ApiResponse,
) {
    let Some(staged) = staged else {
        return;
    };
    let respond = |response: ApiResponse| {
        to_api
            .send(response)
            .map_err(|_| ())
            .expect("one-shot channel closed");
    };

    let staged_is_pause = *staged == VmmAction::Pause;
    respond(vmm::vstate::farplane::outside_capture_epoch(|| {
        execute(*staged)
    }));
    if !staged_is_pause {
        return;
    }

    // A pause switches to blocking receives on `from_api` until the resume arrives. Control is
    // never handed back to the event manager in that state, so device emulation is implicitly
    // paused and so is everything else the loop drives, such as the metric flush timer.
    loop {
        let request = from_api.recv().expect("Error receiving API request.");
        let request_is_resume = *request == VmmAction::Resume;
        respond(vmm::vstate::farplane::outside_capture_epoch(|| {
            execute(*request)
        }));
        if request_is_resume {
            return;
        }
    }
}
impl MutEventSubscriber for ApiServerAdapter {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        if source == self.api_event_fd.as_raw_fd() && event_set == EventSet::IN {
            let _ = self.api_event_fd.read();
            match self.from_api.try_recv() {
                Ok(api_request) => {
                    self.request = Some(api_request);
                }
                Err(TryRecvError::Empty) => {
                    warn_unrestricted!("Got a spurious notification from api thread");
                }
                Err(TryRecvError::Disconnected) => {
                    panic!("The channel's sending half was disconnected. Cannot receive data.");
                }
            };
        } else {
            error_unrestricted!("Spurious EventManager event for handler: ApiServerAdapter");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.api_event_fd, EventSet::IN)) {
            error_unrestricted!("Failed to register activate event: {}", err);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_with_api(
    seccomp_filters: &mut BpfThreadMap,
    config_json: Option<String>,
    bind_path: PathBuf,
    instance_info: InstanceInfo,
    process_time_reporter: ProcessTimeReporter,
    boot_timer_enabled: bool,
    pci_enabled: bool,
    api_payload_limit: usize,
) -> Result<(), ApiServerError> {
    // FD to notify of API events. This is a blocking eventfd by design.
    // It is used in the config/pre-boot loop which is a simple blocking loop
    // which only consumes API events.
    let api_event_fd = EventFd::new(libc::EFD_SEMAPHORE).expect("Cannot create API Eventfd.");
    // FD used to signal API thread to stop/shutdown.
    let api_kill_switch = EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create API kill switch.");

    // Channels for both directions between Vmm and Api threads.
    let (to_vmm, from_api) = channel();
    let (to_api, from_vmm) = channel();

    let to_vmm_event_fd = api_event_fd
        .try_clone()
        .expect("Failed to clone API event FD");
    let api_seccomp_filter = seccomp_filters
        .remove("api")
        .expect("Missing seccomp filter for API thread.");

    let mut server = match HttpServer::new(&bind_path) {
        Ok(s) => s,
        Err(ServerError::IOError(inner)) if inner.kind() == std::io::ErrorKind::AddrInUse => {
            let sock_path = bind_path.display().to_string();
            return Err(ApiServerError::FailedToBindSocket(sock_path));
        }
        Err(err) => {
            return Err(ApiServerError::FailedToBindAndRunHttpServer(err));
        }
    };
    info_unrestricted!("Listening on API socket ({bind_path:?}).");

    let api_kill_switch_clone = api_kill_switch
        .try_clone()
        .expect("Failed to clone API kill switch");

    server
        .add_kill_switch(api_kill_switch_clone)
        .expect("Cannot add HTTP server kill switch");

    // Start the separate API thread.
    let api_thread = thread::Builder::new()
        .name("fc_api".to_owned())
        .spawn(move || {
            ApiServer::new(to_vmm, from_vmm, to_vmm_event_fd).run(
                server,
                process_time_reporter,
                &api_seccomp_filter,
                api_payload_limit,
            );
        })
        .expect("API thread spawn failed.");

    let mut event_manager = EventManager::new().expect("Unable to create EventManager");

    // Create the firecracker metrics object responsible for periodically printing metrics.
    let firecracker_metrics = Arc::new(Mutex::new(super::metrics::PeriodicMetrics::new()));
    event_manager.add_subscriber(firecracker_metrics.clone());

    // Configure, build and start the microVM.
    let build_result = match config_json {
        Some(json) => super::build_microvm_from_json(
            seccomp_filters,
            &mut event_manager,
            json,
            instance_info,
            boot_timer_enabled,
            pci_enabled,
        )
        .map_err(ApiServerError::BuildFromJson),
        None => PrebootApiController::build_microvm_from_requests(
            seccomp_filters,
            &mut event_manager,
            instance_info,
            ApiRequestChannels {
                from_api: &from_api,
                to_api: &to_api,
                event_fd: &api_event_fd,
            },
            boot_timer_enabled,
            pci_enabled,
        )
        .map_err(ApiServerError::BuildMicroVmError),
    };

    let result = build_result.and_then(|vmm| {
        firecracker_metrics
            .lock()
            .expect("Poisoned lock")
            .start(super::metrics::WRITE_METRICS_PERIOD_MS);

        ApiServerAdapter::run_microvm(api_event_fd, from_api, to_api, vmm, &mut event_manager)
    });

    api_kill_switch.write(1).unwrap();
    // This call to thread::join() should block until the API thread has processed the
    // shutdown-internal and returns from its function.
    api_thread.join().expect("Api thread should join");

    result
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use vmm::rpc_interface::VmmData;

    use super::*;

    /// An action staged before a capture epoch closed the gate does not reach the microVM inside
    /// the epoch: it waits for the epoch to end, so it cannot mutate VM or device state between
    /// the vmstate and the dirty harvest.
    #[test]
    fn a_staged_action_waits_for_the_capture_epoch_to_end() {
        static EXECUTED: AtomicBool = AtomicBool::new(false);

        let (_to_vmm, from_api) = channel::<ApiRequest>();
        let (to_api, from_vmm) = channel::<ApiResponse>();

        // The epoch closes with the Resume already staged, exactly as a capture that starts while
        // the API thread has handed an action over leaves it.
        vmm::vstate::farplane::gate().close();

        let served = thread::spawn(move || {
            serve_actions(
                Some(Box::new(VmmAction::Resume)),
                &from_api,
                &to_api,
                |action| {
                    assert_eq!(action, VmmAction::Resume);
                    EXECUTED.store(true, Ordering::SeqCst);
                    Box::new(Ok(VmmData::Empty))
                },
            );
        });

        // The gate is closed, so no amount of waiting lets the action run.
        thread::sleep(Duration::from_millis(50));
        assert!(
            !EXECUTED.load(Ordering::SeqCst),
            "the action ran inside the capture epoch"
        );
        assert!(
            from_vmm.try_recv().is_err(),
            "a response was sent for an action that must not have run"
        );

        vmm::vstate::farplane::gate().open();

        served.join().expect("action thread panicked");
        assert!(
            EXECUTED.load(Ordering::SeqCst),
            "the action did not run once the epoch ended"
        );
        assert!(
            matches!(*from_vmm.recv().expect("no response"), Ok(VmmData::Empty)),
            "the action's response did not reach the API thread"
        );
    }
}
