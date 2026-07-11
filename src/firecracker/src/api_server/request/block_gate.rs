// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::drive::BlockGateConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_block_gate(body: &Body) -> Result<ParsedRequest, RequestError> {
    let config = serde_json::from_slice::<BlockGateConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetBlockGate(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_block_gate() {
        let action = vmm_action_from_request(
            parse_put_block_gate(&Body::new(r#"{"engaged":true}"#)).unwrap(),
        );
        assert_eq!(
            action,
            VmmAction::SetBlockGate(BlockGateConfig { engaged: true })
        );

        let action = vmm_action_from_request(
            parse_put_block_gate(&Body::new(r#"{"engaged":false}"#)).unwrap(),
        );
        assert_eq!(
            action,
            VmmAction::SetBlockGate(BlockGateConfig { engaged: false })
        );

        for invalid_body in [
            r#"{}"#,
            r#"{"engaged":"true"}"#,
            r#"{"engaged":true,"unknown":false}"#,
            r#"{"engaged":true"#,
        ] {
            parse_put_block_gate(&Body::new(invalid_body)).unwrap_err();
        }
    }
}
