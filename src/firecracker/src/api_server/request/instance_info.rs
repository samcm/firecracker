// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use micro_http::StatusCode;
use vmm::logger::{IncMetric, METRICS};
use vmm::rpc_interface::VmmData;
use vmm::vmm_config::instance_info::InstanceInfo;

use super::super::parsed_request::{ParsedRequest, RequestError};

/// Answers from the published description rather than the microVM, so the state stays observable
/// while a capture epoch has the microVM's event loop parked.
pub(crate) fn parse_get_instance_info() -> Result<ParsedRequest, RequestError> {
    METRICS.get_api_requests.instance_info_count.inc();
    let info = InstanceInfo::observe().ok_or(RequestError::Generic(
        StatusCode::ServiceUnavailable,
        "The instance description is not published yet.".to_string(),
    ))?;
    Ok(ParsedRequest::new_immediate(VmmData::InstanceInformation(
        info,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::RequestAction;

    #[test]
    fn test_parse_get_instance_info_request() {
        InstanceInfo {
            id: "instance".to_string(),
            ..Default::default()
        }
        .publish();
        match parse_get_instance_info().unwrap().into_parts() {
            (RequestAction::Immediate(data), _) => {
                let VmmData::InstanceInformation(info) = *data else {
                    panic!("Test failed.")
                };
                assert_eq!(info.id, "instance");
            }
            _ => panic!("Test failed."),
        }
    }
}
