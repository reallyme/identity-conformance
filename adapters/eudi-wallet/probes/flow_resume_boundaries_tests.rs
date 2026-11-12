// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent write-ahead flow-resumption regression probe.

use reallyme_wallet::flows::{
    execution_resume_decision, validate_execution_record, ExecutionErrorReason,
    ExecutionResumeDecision,
};
use reallyme_wallet::types::{
    FlowDisposition, FlowEffect, FlowEffectKind, FlowEffectState, FlowExecutionRecord, FlowKind,
    FlowSnapshotId, UnixTimestamp, WalletTypesError,
};

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn request_digest(bytes: &[u8]) -> [u8; 32] {
    crypto_sha2_256::digest(bytes).into_bytes()
}

fn effect(
    id: u8,
    kind: FlowEffectKind,
    state: FlowEffectState,
    request_bytes: &[u8],
) -> FlowEffect {
    FlowEffect {
        request_bytes: request_bytes.to_vec(),
        id: [id; 32],
        request_digest: request_digest(request_bytes),
        kind,
        state,
    }
}

fn record(
    disposition: FlowDisposition,
    effects: Vec<FlowEffect>,
) -> Result<FlowExecutionRecord, WalletTypesError> {
    Ok(FlowExecutionRecord {
        id: FlowSnapshotId::new("framework-flow-1".to_owned())?,
        kind: FlowKind::Presentation,
        intent_digest: [0x41; 32],
        disposition,
        effects,
        snapshot: vec![0x51],
        expires_at: timestamp(100)?,
        updated_at: timestamp(10)?,
    })
}

fn assert_invalid(record: &FlowExecutionRecord) {
    assert!(matches!(
        validate_execution_record(record),
        Err(error) if error.reason == ExecutionErrorReason::InvalidRecord
    ));
}

#[test]
fn reserved_delivery_never_becomes_safe_to_repeat() -> Result<(), WalletTypesError> {
    for kind in [FlowEffectKind::Submission, FlowEffectKind::StorageCommit] {
        let pending = record(
            FlowDisposition::Active,
            vec![effect(1, kind, FlowEffectState::Reserved, b"exact request")],
        )?;
        assert_eq!(
            execution_resume_decision(&pending, timestamp(20)?).ok(),
            Some(ExecutionResumeDecision::ReconcileOnly)
        );
        assert_eq!(
            execution_resume_decision(&pending, timestamp(101)?).ok(),
            Some(ExecutionResumeDecision::ReconcileOnly)
        );
    }
    Ok(())
}

#[test]
fn changed_bytes_duplicate_ids_and_multiple_reservations_are_rejected(
) -> Result<(), WalletTypesError> {
    let valid_effect = effect(
        1,
        FlowEffectKind::Submission,
        FlowEffectState::Reserved,
        b"exact request",
    );

    let mut tampered = record(FlowDisposition::Active, vec![valid_effect.clone()])?;
    tampered.effects[0].request_bytes = b"different request".to_vec();
    assert_invalid(&tampered);

    let duplicate_id = record(
        FlowDisposition::Active,
        vec![
            effect(
                1,
                FlowEffectKind::Consent,
                FlowEffectState::Confirmed,
                b"consent",
            ),
            valid_effect.clone(),
        ],
    )?;
    assert_invalid(&duplicate_id);

    let multiple_reservations = record(
        FlowDisposition::Active,
        vec![
            valid_effect,
            effect(
                2,
                FlowEffectKind::StorageCommit,
                FlowEffectState::Reserved,
                b"storage commit",
            ),
        ],
    )?;
    assert_invalid(&multiple_reservations);
    Ok(())
}

#[test]
fn time_and_terminal_dispositions_cannot_reauthorize_work() -> Result<(), WalletTypesError> {
    let active = record(FlowDisposition::Active, Vec::new())?;
    assert!(matches!(
        execution_resume_decision(&active, timestamp(9)?),
        Err(error) if error.reason == ExecutionErrorReason::TimeRollback
    ));
    assert!(matches!(
        execution_resume_decision(&active, timestamp(100)?),
        Err(error) if error.reason == ExecutionErrorReason::Expired
    ));

    let delivery_unknown = record(
        FlowDisposition::DeliveryUnknown,
        vec![effect(
            1,
            FlowEffectKind::Submission,
            FlowEffectState::Confirmed,
            b"submitted request",
        )],
    )?;
    assert_eq!(
        execution_resume_decision(&delivery_unknown, timestamp(20)?).ok(),
        Some(ExecutionResumeDecision::Terminal(
            FlowDisposition::DeliveryUnknown
        ))
    );

    let completed = record(
        FlowDisposition::Completed,
        vec![effect(
            1,
            FlowEffectKind::Submission,
            FlowEffectState::Confirmed,
            b"submitted request",
        )],
    )?;
    assert_eq!(
        execution_resume_decision(&completed, timestamp(20)?).ok(),
        Some(ExecutionResumeDecision::Terminal(
            FlowDisposition::Completed
        ))
    );
    Ok(())
}

#[test]
fn incompatible_terminal_states_and_effects_fail_validation() -> Result<(), WalletTypesError> {
    let delivery_without_delivery_effect = record(
        FlowDisposition::DeliveryUnknown,
        vec![effect(
            1,
            FlowEffectKind::Consent,
            FlowEffectState::Confirmed,
            b"consent",
        )],
    )?;
    assert_invalid(&delivery_without_delivery_effect);

    let completed_without_required_effect = record(
        FlowDisposition::Completed,
        vec![effect(
            1,
            FlowEffectKind::StorageCommit,
            FlowEffectState::Confirmed,
            b"storage commit",
        )],
    )?;
    assert_invalid(&completed_without_required_effect);

    let cancelled_after_possible_delivery = record(
        FlowDisposition::Cancelled,
        vec![effect(
            1,
            FlowEffectKind::Submission,
            FlowEffectState::Confirmed,
            b"submitted request",
        )],
    )?;
    assert_invalid(&cancelled_after_possible_delivery);
    Ok(())
}
