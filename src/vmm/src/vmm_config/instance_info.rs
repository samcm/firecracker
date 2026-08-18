// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::{self, Display, Formatter};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

use serde::{Serialize, ser};

use crate::vstate::farplane::FarplaneState;

static DESCRIPTION: Mutex<Option<InstanceInfo>> = Mutex::new(None);
static VCPU_STATE: AtomicU8 = AtomicU8::new(VmState::NotStarted as u8);

/// Enumerates microVM runtime states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum VmState {
    /// Vm not started (yet)
    #[default]
    NotStarted = 0,
    /// Vm is Paused
    Paused = 1,
    /// Vm is running
    Running = 2,
}

impl VmState {
    /// Publishes the vCPU state every observer reports.
    pub fn publish(self) {
        VCPU_STATE.store(self as u8, Ordering::Release);
    }

    /// Returns the published vCPU state.
    pub fn load() -> Self {
        match VCPU_STATE.load(Ordering::Acquire) {
            0 => Self::NotStarted,
            1 => Self::Paused,
            _ => Self::Running,
        }
    }
}

impl Display for VmState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            VmState::NotStarted => write!(f, "Not started"),
            VmState::Paused => write!(f, "Paused"),
            VmState::Running => write!(f, "Running"),
        }
    }
}

impl ser::Serialize for VmState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

/// Description of the microVM instance, as reported by the instance information endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InstanceInfo {
    /// The ID of the microVM.
    pub id: String,
    /// Whether the microVM is not started/running/paused.
    pub state: VmState,
    /// The version of the VMM that runs the microVM.
    pub vmm_version: String,
    /// The name of the application that runs the microVM.
    pub app_name: String,
    /// Farplane memory-backend observation.
    pub farplane: FarplaneState,
}

impl InstanceInfo {
    /// Publishes the immutable part of the description, so that a reader needs no microVM.
    pub fn publish(&self) {
        *DESCRIPTION.lock().expect("Poisoned lock") = Some(self.clone());
    }

    /// Samples the published description together with the live vCPU and memory-backend state.
    ///
    /// Reading it takes no lock the microVM holds, so the state stays observable while a capture
    /// epoch has the event loop of the microVM parked.
    pub fn observe() -> Option<Self> {
        let mut info = DESCRIPTION.lock().expect("Poisoned lock").clone()?;
        info.state = VmState::load();
        info.farplane = FarplaneState::observe();
        Some(info)
    }
}
