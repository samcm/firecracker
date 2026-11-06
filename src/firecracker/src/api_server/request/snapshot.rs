// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::snapshot::{LoadSnapshotParams, Vm, VmState};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::super::request::{Body, Method, StatusCode};

pub(crate) fn parse_put_snapshot(
    body: &Body,
    request_type_from_path: Option<&str>,
) -> Result<ParsedRequest, RequestError> {
    match request_type_from_path {
        Some("load") => parse_put_snapshot_load(body),
        Some(request_type) => Err(RequestError::InvalidPathMethod(
            format!("/snapshot/{}", request_type),
            Method::Put,
        )),
        None => Err(RequestError::Generic(
            StatusCode::BadRequest,
            "Missing snapshot operation type.".to_string(),
        )),
    }
}

pub(crate) fn parse_patch_vm_state(body: &Body) -> Result<ParsedRequest, RequestError> {
    if vmm::vstate::farplane::FarplaneBackend::capture_in_progress() {
        return Err(RequestError::Generic(
            StatusCode::Conflict,
            "capture_in_progress".to_string(),
        ));
    }
    let vm = serde_json::from_slice::<Vm>(body.raw())?;
    match vm.state {
        VmState::Paused => Ok(ParsedRequest::new_sync(VmmAction::Pause)),
        VmState::Resumed => Ok(ParsedRequest::new_sync(VmmAction::Resume)),
    }
}

fn parse_put_snapshot_load(body: &Body) -> Result<ParsedRequest, RequestError> {
    let snapshot_params = serde_json::from_slice::<LoadSnapshotParams>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::LoadSnapshot(
        snapshot_params,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_snapshot_load() {
        let body = r#"{"resume_vm": true}"#;
        assert_eq!(
            vmm_action_from_request(parse_put_snapshot(&Body::new(body), Some("load")).unwrap()),
            VmmAction::LoadSnapshot(LoadSnapshotParams { resume_vm: true })
        );
    }

    #[test]
    fn test_parse_put_snapshot_create_absent() {
        let body = r#"{"snapshot_path":"foo","mem_file_path":"bar"}"#;
        parse_put_snapshot(&Body::new(body), Some("create")).unwrap_err();
    }

    #[test]
    fn test_legacy_load_fields_unknown() {
        let body = r#"{"resume_vm":true,"snapshot_path":"foo"}"#;
        parse_put_snapshot(&Body::new(body), Some("load")).unwrap_err();
    }
}
