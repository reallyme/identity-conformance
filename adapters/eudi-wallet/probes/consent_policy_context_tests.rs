// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent consent-policy transcript regression probe.

use reallyme_wallet::consent::{consent_policy_digest, ConsentErrorReason};
use reallyme_wallet::types::{
    ConsentPolicyChoice, ConsentPolicyContext, ConsentRetention, NonEmptyIdentifier, UnixTimestamp,
    WalletTypesError,
};

const GOLDEN_DIGEST: [u8; 32] = [
    0x80, 0xf4, 0x2b, 0x43, 0x7e, 0x5b, 0x02, 0x2a, 0x20, 0xf7, 0xaf, 0x4b, 0xeb, 0x46, 0xd7, 0xea,
    0xe4, 0x82, 0x7d, 0x7d, 0xbf, 0x6e, 0x52, 0x90, 0xec, 0x64, 0x45, 0xb0, 0xcb, 0xb2, 0xbc, 0xdd,
];

fn identifier(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn policy(
    id: &str,
    version: &str,
    document_digest: [u8; 32],
    mandatory: bool,
    accepted: bool,
) -> Result<ConsentPolicyChoice, WalletTypesError> {
    Ok(ConsentPolicyChoice {
        id: identifier(id)?,
        version: identifier(version)?,
        document_digest,
        mandatory,
        accepted,
    })
}

fn context() -> Result<ConsentPolicyContext, WalletTypesError> {
    Ok(ConsentPolicyContext {
        purpose: identifier("age-assurance")?,
        retention: ConsentRetention::Until(UnixTimestamp::from_seconds(1_900_000_000)?),
        policies: vec![
            policy("privacy-notice", "2026.11", [0x11; 32], true, true)?,
            policy("retention-policy", "3", [0x22; 32], false, false)?,
        ],
        transaction_digest: [0x33; 32],
    })
}

fn assert_policy_context_mismatch(context: &ConsentPolicyContext) {
    assert!(matches!(
        consent_policy_digest(context),
        Err(error) if error.reason == ConsentErrorReason::PolicyContextMismatch
    ));
}

#[test]
fn consent_policy_digest_matches_the_independent_golden_transcript() -> Result<(), WalletTypesError>
{
    // The constant was computed from the documented length-prefixed transcript,
    // outside the Wallet implementation. It is deliberately not self-derived.
    assert_eq!(consent_policy_digest(&context()?).ok(), Some(GOLDEN_DIGEST));
    Ok(())
}

#[test]
fn every_approved_term_changes_the_bound_digest() -> Result<(), WalletTypesError> {
    let original = context()?;
    let original_digest = consent_policy_digest(&original).ok();
    let mut variants = Vec::new();

    let mut changed = original.clone();
    changed.purpose = identifier("identity-assurance")?;
    variants.push(changed);

    let mut changed = original.clone();
    changed.retention = ConsentRetention::NoRetention;
    variants.push(changed);

    let mut changed = original.clone();
    changed.retention = ConsentRetention::Until(UnixTimestamp::from_seconds(1_900_000_001)?);
    variants.push(changed);

    let mut changed = original.clone();
    changed.policies[0].id = identifier("privacy-notice-v2")?;
    variants.push(changed);

    let mut changed = original.clone();
    changed.policies[0].version = identifier("2026.12")?;
    variants.push(changed);

    let mut changed = original.clone();
    changed.policies[0].document_digest = [0x12; 32];
    variants.push(changed);

    let mut changed = original.clone();
    changed.policies[0].mandatory = false;
    variants.push(changed);

    let mut changed = original.clone();
    changed.policies[1].accepted = true;
    variants.push(changed);

    let mut changed = original.clone();
    changed.transaction_digest = [0x34; 32];
    variants.push(changed);

    for variant in variants {
        assert_ne!(consent_policy_digest(&variant).ok(), original_digest);
    }
    Ok(())
}

#[test]
fn invalid_or_ambiguous_policy_contexts_fail_closed() -> Result<(), WalletTypesError> {
    let original = context()?;

    let mut declined_mandatory = original.clone();
    declined_mandatory.policies[0].accepted = false;
    assert_policy_context_mismatch(&declined_mandatory);

    let mut unsorted = original.clone();
    unsorted.policies.swap(0, 1);
    assert_policy_context_mismatch(&unsorted);

    let mut duplicate = original.clone();
    duplicate.policies[1].id = duplicate.policies[0].id.clone();
    assert_policy_context_mismatch(&duplicate);

    let mut zero_document_digest = original.clone();
    zero_document_digest.policies[0].document_digest = [0; 32];
    assert_policy_context_mismatch(&zero_document_digest);

    let mut zero_transaction_digest = original.clone();
    zero_transaction_digest.transaction_digest = [0; 32];
    assert_policy_context_mismatch(&zero_transaction_digest);

    let mut too_many = original.clone();
    too_many.policies.clear();
    for index in 0_u8..17 {
        too_many.policies.push(policy(
            &format!("policy-{index:02}"),
            "1",
            [index + 1; 32],
            false,
            true,
        )?);
    }
    assert_policy_context_mismatch(&too_many);
    Ok(())
}

#[test]
fn length_prefixing_separates_ambiguous_text_boundaries() -> Result<(), WalletTypesError> {
    let mut first = context()?;
    first.purpose = identifier("ab")?;
    first.policies = vec![policy("c", "1", [0x44; 32], false, true)?];

    let mut second = first.clone();
    second.purpose = identifier("a")?;
    second.policies[0].id = identifier("bc")?;

    assert_ne!(
        consent_policy_digest(&first).ok(),
        consent_policy_digest(&second).ok()
    );
    Ok(())
}
