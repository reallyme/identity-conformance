// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent Wallet provider-boundary regression probe.

use reallyme_wallet_provider::{
    build_provider_descriptor, ProviderContractError, ProviderExecutorId, ProviderInvocationMode,
    ProviderTransport, ProviderTransportError, ProviderTransportErrorReason,
    ProviderTransportResult, SynchronousProtobufProviderBackend,
};
use reallyme_wallet_runtime::{RecordRevision, RuntimeErrorReason, RuntimeResult};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
enum RecordFamily {
    Did,
    Portable,
    Hardware,
}

impl RecordFamily {
    const fn valid_id(self) -> &'static str {
        match self {
            Self::Did => "did-record-1",
            Self::Portable => "portable-key-1",
            Self::Hardware => "hardware-key-1",
        }
    }
}

const RECORD_FAMILIES: [RecordFamily; 3] = [
    RecordFamily::Did,
    RecordFamily::Portable,
    RecordFamily::Hardware,
];

struct RefusingTransport {
    calls: u32,
}

impl ProviderTransport for RefusingTransport {
    fn invoke(
        &mut self,
        _request: &[u8],
        _maximum_response_bytes: usize,
    ) -> ProviderTransportResult<Zeroizing<Vec<u8>>> {
        self.calls = self.calls.checked_add(1).ok_or_else(rejected)?;
        Err(rejected())
    }
}

type Backend = SynchronousProtobufProviderBackend<RefusingTransport>;

fn rejected() -> ProviderTransportError {
    ProviderTransportError::new(ProviderTransportErrorReason::Rejected)
}

fn backend() -> Result<Backend, ProviderContractError> {
    SynchronousProtobufProviderBackend::new(
        RefusingTransport { calls: 0 },
        &build_provider_descriptor(ProviderInvocationMode::SynchronousNative),
        ProviderExecutorId::new(901)?,
    )
}

fn assert_key_storage_rejected<T>(result: RuntimeResult<T>) {
    assert!(matches!(
        result,
        Err(error) if error.reason == RuntimeErrorReason::KeyStorageRejected
    ));
}

fn exercise_invalid_identity(family: RecordFamily, provider: &mut Backend, record_id: &str) {
    match family {
        RecordFamily::Did => {
            assert_key_storage_rejected(provider.get_did_storage_record(record_id));
            assert_key_storage_rejected(
                provider.delete_did_storage_record(record_id, RecordRevision::new(1)),
            );
        }
        RecordFamily::Portable => {
            assert_key_storage_rejected(provider.get_portable_key_storage_record(record_id));
            assert_key_storage_rejected(
                provider.delete_portable_key_storage_record(record_id, RecordRevision::new(1)),
            );
        }
        RecordFamily::Hardware => {
            assert_key_storage_rejected(provider.get_hardware_key_binding_record(record_id));
            assert_key_storage_rejected(
                provider.delete_hardware_key_binding_record(record_id, RecordRevision::new(1)),
            );
        }
    }
}

fn exercise_valid_read_identity(family: RecordFamily, provider: &mut Backend) {
    let result = match family {
        RecordFamily::Did => provider
            .get_did_storage_record(family.valid_id())
            .map(|_| ()),
        RecordFamily::Portable => provider
            .get_portable_key_storage_record(family.valid_id())
            .map(|_| ()),
        RecordFamily::Hardware => provider
            .get_hardware_key_binding_record(family.valid_id())
            .map(|_| ()),
    };
    assert!(result.is_err());
}

fn exercise_valid_delete_identity(family: RecordFamily, provider: &mut Backend) {
    let result =
        match family {
            RecordFamily::Did => {
                provider.delete_did_storage_record(family.valid_id(), RecordRevision::new(1))
            }
            RecordFamily::Portable => provider
                .delete_portable_key_storage_record(family.valid_id(), RecordRevision::new(1)),
            RecordFamily::Hardware => provider
                .delete_hardware_key_binding_record(family.valid_id(), RecordRevision::new(1)),
        };
    assert!(result.is_err());
}

#[test]
fn invalid_storage_identities_never_reach_the_provider() -> Result<(), ProviderContractError> {
    let oversized = "k".repeat(257);
    for family in RECORD_FAMILIES {
        // The negative assertions below must not pass because the adapter simply
        // rejects every request before invoking the selected provider.
        let mut valid_read_control = backend()?;
        exercise_valid_read_identity(family, &mut valid_read_control);
        assert_eq!(valid_read_control.transport().calls, 1);
        let mut valid_delete_control = backend()?;
        exercise_valid_delete_identity(family, &mut valid_delete_control);
        assert_eq!(valid_delete_control.transport().calls, 1);

        for record_id in [
            "",
            "../record",
            "folder/%2e%2e/record",
            "folder/%252e%252e/record",
            "nul\0byte",
            "line\nbreak",
            "record\\slot",
            oversized.as_str(),
        ] {
            let mut provider = backend()?;
            exercise_invalid_identity(family, &mut provider, record_id);
            assert_eq!(provider.transport().calls, 0);
        }
        let mut provider = backend()?;
        match family {
            RecordFamily::Did => assert_key_storage_rejected(
                provider.delete_did_storage_record(family.valid_id(), RecordRevision::new(0)),
            ),
            RecordFamily::Portable => assert_key_storage_rejected(
                provider
                    .delete_portable_key_storage_record(family.valid_id(), RecordRevision::new(0)),
            ),
            RecordFamily::Hardware => assert_key_storage_rejected(
                provider
                    .delete_hardware_key_binding_record(family.valid_id(), RecordRevision::new(0)),
            ),
        }
        assert_eq!(provider.transport().calls, 0);
    }
    Ok(())
}
