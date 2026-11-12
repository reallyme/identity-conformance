// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent key-custody and bounded-codec regression probe.

use buffa::{EnumValue, MessageField};
use openid4vci_proto::generated::proto::reallyme::openid4vci::v1 as openid4vci_pb;
use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1 as crypto_pb;
use reallyme_ssi_proto::generated::proto::identity::credential::v1 as credential_pb;
use reallyme_ssi_proto::generated::proto::identity::did::v1 as did_pb;
use reallyme_wallet_proto::generated::proto::reallyme::wallet::v1 as pb;
use reallyme_wallet_proto_codec::decode::{
    decode_hardware_key_binding_record, decode_portable_key_storage_record,
};
use reallyme_wallet_proto_codec::encode::{
    encode_hardware_key_binding_record, encode_portable_key_storage_record,
};
use reallyme_wallet_proto_codec::{
    validate_hardware_key_binding_record, validate_portable_key_storage_record, ProtoErrorReason,
    ProtoResult, MAX_WALLET_PROTO_MESSAGE_BYTES,
};

const P256_GENERATOR_COMPRESSED: [u8; 33] = [
    0x03, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96,
];
const P256_GENERATOR_UNCOMPRESSED: [u8; 65] = [
    0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];
const P256_DOUBLE_GENERATOR_COMPRESSED: [u8; 33] = [
    0x03, 0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a,
    0xc3, 0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99,
    0x78,
];

#[derive(Debug, thiserror::Error)]
enum ProbeError {
    #[error("framework probe arithmetic overflow")]
    ArithmeticOverflow,
}

fn signing_algorithm() -> crypto_pb::CryptoAlgorithmIdentifier {
    crypto_pb::CryptoAlgorithmIdentifier {
        algorithm: Some(
            crypto_pb::crypto_algorithm_identifier::Algorithm::Signature(EnumValue::from(
                crypto_pb::SignatureAlgorithm::SIGNATURE_ALGORITHM_ECDSA_P256_SHA256,
            )),
        ),
        ..Default::default()
    }
}

fn wrapping_algorithm() -> crypto_pb::CryptoAlgorithmIdentifier {
    crypto_pb::CryptoAlgorithmIdentifier {
        algorithm: Some(crypto_pb::crypto_algorithm_identifier::Algorithm::KeyWrap(
            EnumValue::from(crypto_pb::KeyWrapAlgorithm::KEY_WRAP_ALGORITHM_AES_256_KW),
        )),
        ..Default::default()
    }
}

fn timestamp() -> MessageField<pb::UnixTimestamp, buffa::Inline<pb::UnixTimestamp>> {
    MessageField::some(pb::UnixTimestamp {
        seconds: 1_800_000_000,
        ..Default::default()
    })
}

fn verification_method(public_key: &[u8]) -> did_pb::VerificationMethod {
    let mut jwk = crypto_pb::JsonWebKey::default();
    jwk.algorithm = MessageField::some(signing_algorithm());
    jwk.public_key = public_key.to_vec();
    jwk.canonical_jcs = br#"{"crv":"P-256","kty":"EC"}"#.to_vec();
    did_pb::VerificationMethod {
        id: "did:example:framework#key-1".to_owned(),
        r#type: EnumValue::from(
            did_pb::VerificationMethodType::VERIFICATION_METHOD_TYPE_JSON_WEB_KEY,
        ),
        controller: "did:example:framework".to_owned(),
        algorithm: MessageField::some(signing_algorithm()),
        public_key: Some(did_pb::verification_method::PublicKey::PublicKeyJwk(
            Box::new(jwk),
        )),
        ..Default::default()
    }
}

fn subject_key(public_key: &[u8]) -> credential_pb::PublicKeyRef {
    credential_pb::PublicKeyRef {
        reference: MessageField::some(credential_pb::KeyReference {
            kind: Some(
                credential_pb::__buffa::oneof::key_reference::Kind::DidVerificationMethod(
                    "did:example:framework#key-1".to_owned(),
                ),
            ),
            ..Default::default()
        }),
        public_key: MessageField::some(credential_pb::PublicKeyMaterial {
            alg: EnumValue::from(credential_pb::Algorithm::ALGORITHM_P_256),
            representation: Some(
                credential_pb::__buffa::oneof::public_key_material::Representation::Raw(
                    Box::new(credential_pb::RawPublicKey {
                        serialization: EnumValue::from(
                            credential_pb::RawPublicKeySerialization::RAW_PUBLIC_KEY_SERIALIZATION_SEC1_COMPRESSED,
                        ),
                        bytes: public_key.to_vec(),
                        ..Default::default()
                    }),
                ),
            ),
            ..Default::default()
        }),
        assurance: MessageField::some(credential_pb::KeyAssurance {
            kind: Some(credential_pb::__buffa::oneof::key_assurance::Kind::None(
                Box::default(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[allow(clippy::field_reassign_with_default)]
fn portable_record() -> pb::PortableKeyStorageRecord {
    let mut record = pb::PortableKeyStorageRecord::default();
    record.record_id = "portable-key-1".to_owned();
    record.did_record_id = "did-record-1".to_owned();
    record.verification_method =
        MessageField::some(verification_method(&P256_GENERATOR_COMPRESSED));
    record.credential_subject_key = MessageField::some(subject_key(&P256_GENERATOR_COMPRESSED));
    record.purpose = EnumValue::from(crypto_pb::PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING);
    record.custody = EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_WALLET_SOFTWARE);
    record.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_PORTABLE);
    record.protection =
        EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_WRAPPED_IDENTITY_KEY_SET);
    record.credential_formats = vec![EnumValue::from(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT,
    )];
    record.wrapped_identity_key_set = vec![0xa5; 24];
    record.created_at = timestamp();
    record.wrapping_algorithm = MessageField::some(wrapping_algorithm());
    record
}

#[allow(clippy::field_reassign_with_default)]
fn platform_record() -> pb::HardwareKeyBindingRecord {
    let mut handle = crypto_pb::CryptoPlatformPrivateKeyHandle::default();
    handle.provider =
        EnumValue::from(crypto_pb::PlatformKeyProvider::PLATFORM_KEY_PROVIDER_APPLE_KEYCHAIN);
    handle.purpose = EnumValue::from(crypto_pb::PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING);
    handle.algorithm = MessageField::some(signing_algorithm());
    handle.opaque_handle = vec![0xb5; 32];
    handle.public_key = P256_GENERATOR_UNCOMPRESSED.to_vec();
    handle.actual_security_level = EnumValue::from(
        crypto_pb::PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE,
    );
    handle.requested_security_level = EnumValue::from(
        crypto_pb::PlatformKeySecurityLevel::PLATFORM_KEY_SECURITY_LEVEL_SECURE_ENCLAVE,
    );

    let mut record = pb::HardwareKeyBindingRecord::default();
    record.record_id = "hardware-key-1".to_owned();
    record.did_record_id = "did-record-1".to_owned();
    record.verification_method =
        MessageField::some(verification_method(&P256_GENERATOR_COMPRESSED));
    record.credential_subject_key = MessageField::some(subject_key(&P256_GENERATOR_COMPRESSED));
    record.purpose = EnumValue::from(crypto_pb::PlatformKeyPurpose::PLATFORM_KEY_PURPOSE_SIGNING);
    record.custody = EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_PLATFORM_HARDWARE);
    record.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_NON_EXPORTABLE);
    record.protection =
        EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_PLATFORM_HARDWARE_BOUND);
    record.credential_formats = vec![EnumValue::from(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT,
    )];
    record.binding =
        Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(Box::new(handle)));
    record.created_at = timestamp();
    record
}

#[test]
fn portable_material_cannot_claim_hardware_custody() -> ProtoResult<()> {
    let portable = portable_record();
    let encoded = encode_portable_key_storage_record(&portable)?;
    assert_eq!(decode_portable_key_storage_record(&encoded)?, portable);

    let mut relabelled = portable.clone();
    relabelled.custody =
        EnumValue::from(pb::WalletKeyCustody::WALLET_KEY_CUSTODY_PLATFORM_HARDWARE);
    assert!(validate_portable_key_storage_record(&relabelled).is_err());

    let mut relabelled = portable.clone();
    relabelled.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_NON_EXPORTABLE);
    assert!(validate_portable_key_storage_record(&relabelled).is_err());

    let mut relabelled = portable;
    relabelled.protection =
        EnumValue::from(pb::WalletKeyProtection::WALLET_KEY_PROTECTION_PLATFORM_HARDWARE_BOUND);
    assert!(validate_portable_key_storage_record(&relabelled).is_err());
    Ok(())
}

#[test]
fn hardware_material_is_non_exportable_and_key_bound() -> ProtoResult<()> {
    let hardware = platform_record();
    let encoded = encode_hardware_key_binding_record(&hardware)?;
    assert_eq!(decode_hardware_key_binding_record(&encoded)?, hardware);

    let mut exportable = hardware.clone();
    exportable.exportability =
        EnumValue::from(pb::WalletKeyExportability::WALLET_KEY_EXPORTABILITY_PORTABLE);
    assert!(validate_hardware_key_binding_record(&exportable).is_err());

    let mut substituted = hardware.clone();
    if let Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(handle)) =
        substituted.binding.as_mut()
    {
        handle.public_key = P256_DOUBLE_GENERATOR_COMPRESSED.to_vec();
    }
    assert!(validate_hardware_key_binding_record(&substituted).is_err());

    let mut substituted = hardware;
    substituted.credential_subject_key =
        MessageField::some(subject_key(&P256_DOUBLE_GENERATOR_COMPRESSED));
    assert!(validate_hardware_key_binding_record(&substituted).is_err());
    Ok(())
}

#[test]
fn malformed_or_ambiguous_key_records_fail_closed() {
    let mut missing_wrapped_material = portable_record();
    missing_wrapped_material.wrapped_identity_key_set.clear();
    assert!(validate_portable_key_storage_record(&missing_wrapped_material).is_err());

    let mut duplicate_format = portable_record();
    duplicate_format.credential_formats.push(EnumValue::from(
        openid4vci_pb::CredentialFormat::CREDENTIAL_FORMAT_DC_SD_JWT,
    ));
    assert!(validate_portable_key_storage_record(&duplicate_format).is_err());

    let mut unknown_algorithm = portable_record();
    if let Some(method) = unknown_algorithm.verification_method.as_option_mut() {
        method.algorithm = MessageField::none();
    }
    assert!(validate_portable_key_storage_record(&unknown_algorithm).is_err());

    let mut malformed_point = platform_record();
    if let Some(pb::hardware_key_binding_record::Binding::PlatformPrivateKey(handle)) =
        malformed_point.binding.as_mut()
    {
        handle.public_key = vec![0x03; 33];
    }
    assert!(validate_hardware_key_binding_record(&malformed_point).is_err());
}

#[test]
fn oversized_wire_data_is_rejected_before_domain_construction() -> Result<(), ProbeError> {
    let oversized_length = MAX_WALLET_PROTO_MESSAGE_BYTES
        .checked_add(1)
        .ok_or(ProbeError::ArithmeticOverflow)?;
    let oversized = vec![0_u8; oversized_length];
    assert!(matches!(
        decode_portable_key_storage_record(&oversized),
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
    assert!(matches!(
        decode_hardware_key_binding_record(&oversized),
        Err(error) if error.reason == ProtoErrorReason::MessageTooLarge
    ));
    Ok(())
}
