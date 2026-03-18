// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::enclave::EnclaveConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_enclave(body: &Body) -> Result<ParsedRequest, RequestError> {
    let config = serde_json::from_slice::<EnclaveConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetEnclaveConfig(config)))
}

pub(crate) fn parse_get_enclave() -> Result<ParsedRequest, RequestError> {
    Ok(ParsedRequest::new_sync(VmmAction::GetEnclaveConfig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_put_enclave_request() {
        let json = r#"{
            "debug_mode": true,
            "enclave_cid": 42
        }"#;
        let result = parse_put_enclave(&Body::new(json));
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_put_enclave_minimal() {
        let json = "{}";
        let result = parse_put_enclave(&Body::new(json));
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_put_enclave_invalid() {
        let result = parse_put_enclave(&Body::new("invalid"));
        assert!(result.is_err());
    }
}
