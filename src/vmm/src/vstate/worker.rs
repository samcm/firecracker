// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::thread::{self, JoinHandle};

use crate::seccomp::{BpfProgram, InstallationError, apply_filter};

/// Error starting an [`OwnedWorker`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum WorkerStartError {
    /// Failed to spawn the worker thread: {0}
    Spawn(std::io::Error),
    /// The worker failed to install its seccomp filter: {0}
    Filter(InstallationError),
}

/// A thread that owns a piece of runtime state and returns it when it ends.
#[derive(Debug)]
pub struct OwnedWorker<T> {
    thread: JoinHandle<T>,
}

impl<T: Send + 'static> OwnedWorker<T> {
    /// Moves `state` to a thread built by `builder`, which runs `setup`, installs `filter` and
    /// only then reports ready, before running `body` and returning the state.
    ///
    /// The state crosses to the thread only after the spawn succeeded, and a thread whose filter
    /// fails is joined without running `body`, so on either failure the caller gets its state
    /// back. `setup` runs unconfined, for per-thread work the filter would forbid.
    pub fn start(
        builder: thread::Builder,
        state: T,
        filter: Arc<BpfProgram>,
        setup: impl FnOnce(&mut T) + Send + 'static,
        body: impl FnOnce(&mut T) + Send + 'static,
    ) -> Result<Self, (WorkerStartError, T)> {
        let (state_tx, state_rx) = sync_channel::<T>(1);
        let (ready_tx, ready_rx) = sync_channel(1);
        let spawned = builder.spawn(move || {
            // The sender outlives a successful spawn and sends exactly once.
            let mut state = state_rx.recv().unwrap();
            setup(&mut state);
            let installed = apply_filter(&filter);
            let confined = installed.is_ok();
            // The receiver waits for this message before doing anything else.
            ready_tx.send(installed).unwrap();
            if confined {
                body(&mut state);
            }
            state
        });
        let thread = match spawned {
            Ok(thread) => thread,
            Err(err) => return Err((WorkerStartError::Spawn(err), state)),
        };
        // The thread is blocked receiving it.
        state_tx.send(state).unwrap();
        // The thread reports before it can end, and a panic aborts the process.
        match ready_rx.recv().unwrap() {
            Ok(()) => Ok(OwnedWorker { thread }),
            Err(err) => Err((WorkerStartError::Filter(err), Self::join_thread(thread))),
        }
    }

    /// Waits for the worker to end and returns its state; its thread-local destructors have run.
    pub fn join(self) -> T {
        Self::join_thread(self.thread)
    }

    /// The worker's join handle, e.g. for signalling its thread.
    pub fn handle(&self) -> &JoinHandle<T> {
        &self.thread
    }

    fn join_thread(thread: JoinHandle<T>) -> T {
        // Panics abort the process, so a joined worker always returned its state.
        thread.join().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, channel};

    use super::*;
    use crate::seccomp::BPF_MAX_LEN;

    /// A worker state that serves commands until told to stop.
    #[derive(Debug)]
    struct Served {
        commands: Receiver<Option<u32>>,
        setup_on: Option<thread::ThreadId>,
        served: Vec<u32>,
    }

    fn served() -> (std::sync::mpsc::Sender<Option<u32>>, Served) {
        let (tx, commands) = channel();
        let state = Served {
            commands,
            setup_on: None,
            served: Vec::new(),
        };
        (tx, state)
    }

    fn setup(state: &mut Served) {
        state.setup_on = Some(thread::current().id());
    }

    fn serve(state: &mut Served) {
        while let Some(command) = state.commands.recv().unwrap() {
            state.served.push(command);
        }
    }

    fn too_large_filter() -> Arc<BpfProgram> {
        Arc::new(vec![0; BPF_MAX_LEN + 1])
    }

    #[test]
    fn test_worker_returns_state_after_serving() {
        let (tx, state) = served();
        let worker = OwnedWorker::start(
            thread::Builder::new().name("owned".into()),
            state,
            Arc::new(vec![]),
            setup,
            serve,
        )
        .unwrap();
        let worker_id = worker.handle().thread().id();
        // Commands queued before the stop are served in order before the worker returns.
        tx.send(Some(1)).unwrap();
        tx.send(Some(2)).unwrap();
        tx.send(None).unwrap();
        tx.send(Some(3)).unwrap();
        let mut state = worker.join();
        assert_eq!(state.served, [1, 2]);
        assert_eq!(state.setup_on, Some(worker_id));
        assert_ne!(worker_id, thread::current().id());
        // The unserved command stays with the returned state for the next worker.
        assert_eq!(state.commands.try_recv().unwrap(), Some(3));

        // The same state restarts on a fresh thread.
        state.served.clear();
        let worker = OwnedWorker::start(
            thread::Builder::new(),
            state,
            Arc::new(vec![]),
            setup,
            serve,
        )
        .unwrap();
        tx.send(Some(4)).unwrap();
        tx.send(None).unwrap();
        let state = worker.join();
        assert_eq!(state.served, [4]);
    }

    #[test]
    fn test_worker_filter_failure_returns_state() {
        let (tx, state) = served();
        tx.send(Some(1)).unwrap();
        let (err, state) = OwnedWorker::start(
            thread::Builder::new(),
            state,
            too_large_filter(),
            setup,
            serve,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WorkerStartError::Filter(InstallationError::FilterTooLarge)
        ));
        // Setup ran on the joined thread, the body never did.
        assert!(
            state
                .setup_on
                .is_some_and(|id| id != thread::current().id())
        );
        assert!(state.served.is_empty());
        assert_eq!(state.commands.try_recv().unwrap(), Some(1));
    }

    #[test]
    fn test_worker_spawn_failure_returns_state() {
        let (tx, state) = served();
        tx.send(Some(1)).unwrap();
        // No address space fits this stack, so the thread cannot be created.
        let (err, state) = OwnedWorker::start(
            thread::Builder::new().stack_size(1 << 62),
            state,
            Arc::new(vec![]),
            setup,
            serve,
        )
        .unwrap_err();
        assert!(matches!(err, WorkerStartError::Spawn(_)));
        assert!(state.setup_on.is_none());
        assert_eq!(state.commands.try_recv().unwrap(), Some(1));
    }
}
