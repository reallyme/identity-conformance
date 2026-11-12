// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Independent Wallet Unit lifecycle regression probe.

use reallyme_wallet::lifecycle::{
    apply_wallet_lifecycle_event, ensure_wallet_operation_allowed, new_wallet_lifecycle,
    restore_wallet_lifecycle, validate_wallet_lifecycle_successor, LifecycleError,
    LifecycleErrorReason, WalletLifecycleEvent, WalletLifecycleEvidenceKind,
    WalletLifecycleEvidenceRecord, WalletLifecycleRecord, WalletLifecycleState, WalletOperation,
};
use reallyme_wallet::types::{NonEmptyIdentifier, UnixTimestamp, WalletTypesError};

#[derive(Debug, thiserror::Error)]
enum ProbeError {
    #[error("framework lifecycle fixture contains an invalid Wallet type")]
    WalletType(#[from] WalletTypesError),
    #[error("framework lifecycle fixture contains an invalid transition")]
    Lifecycle(#[from] LifecycleError),
}

fn identifier(value: &str) -> Result<NonEmptyIdentifier, WalletTypesError> {
    NonEmptyIdentifier::new(value.to_owned())
}

fn timestamp(seconds: i64) -> Result<UnixTimestamp, WalletTypesError> {
    UnixTimestamp::from_seconds(seconds)
}

fn evidence_kind(
    event: WalletLifecycleEvent,
    state: WalletLifecycleState,
) -> WalletLifecycleEvidenceKind {
    match event {
        WalletLifecycleEvent::BeginProvisioning
        | WalletLifecycleEvent::CompleteProvisioning
        | WalletLifecycleEvent::RetryProvisioning => WalletLifecycleEvidenceKind::Provisioning,
        WalletLifecycleEvent::Suspend => WalletLifecycleEvidenceKind::Suspension,
        WalletLifecycleEvent::Reactivate => WalletLifecycleEvidenceKind::Reactivation,
        WalletLifecycleEvent::BeginRecovery | WalletLifecycleEvent::CompleteRecovery => {
            WalletLifecycleEvidenceKind::Recovery
        }
        WalletLifecycleEvent::BeginMigration | WalletLifecycleEvent::CompleteMigration => {
            WalletLifecycleEvidenceKind::Migration
        }
        WalletLifecycleEvent::BeginWithdrawal | WalletLifecycleEvent::CompleteWithdrawal => {
            WalletLifecycleEvidenceKind::Withdrawal
        }
        WalletLifecycleEvent::BeginDeletion | WalletLifecycleEvent::CompleteDeletion => {
            WalletLifecycleEvidenceKind::Deletion
        }
        WalletLifecycleEvent::MarkFailed => match state {
            WalletLifecycleState::Provisioning => WalletLifecycleEvidenceKind::Provisioning,
            WalletLifecycleState::RecoveryPending => WalletLifecycleEvidenceKind::Recovery,
            WalletLifecycleState::MigrationPending => WalletLifecycleEvidenceKind::Migration,
            WalletLifecycleState::WithdrawalPending => WalletLifecycleEvidenceKind::Withdrawal,
            WalletLifecycleState::DeletionPending => WalletLifecycleEvidenceKind::Deletion,
            _ => WalletLifecycleEvidenceKind::Provisioning,
        },
    }
}

fn evidence(
    record: &WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    at: UnixTimestamp,
) -> Result<WalletLifecycleEvidenceRecord, WalletTypesError> {
    Ok(WalletLifecycleEvidenceRecord {
        id: identifier(&format!(
            "framework-evidence-{:?}-{}",
            event,
            at.as_seconds()
        ))?,
        wallet_instance_id: record.wallet_instance_id().clone(),
        kind: evidence_kind(event, record.state()),
        event,
        occurred_at: at,
        authority_id: identifier("framework-authority")?,
        evidence_ref: identifier("framework-reference")?,
        evidence_digest: vec![0x61; 32],
    })
}

fn apply(
    record: WalletLifecycleRecord,
    event: WalletLifecycleEvent,
    seconds: i64,
) -> Result<WalletLifecycleRecord, ProbeError> {
    let at = timestamp(seconds)?;
    let event_evidence = evidence(&record, event, at)?;
    apply_wallet_lifecycle_event(record, event, at, Some(&event_evidence)).map_err(ProbeError::from)
}

fn active_record() -> Result<WalletLifecycleRecord, ProbeError> {
    let record = new_wallet_lifecycle(identifier("framework-wallet")?, timestamp(1)?);
    let record = apply(record, WalletLifecycleEvent::BeginProvisioning, 2)?;
    apply(record, WalletLifecycleEvent::CompleteProvisioning, 3)
}

#[test]
fn inactive_and_terminal_states_block_regulated_operations() -> Result<(), ProbeError> {
    let active = active_record()?;
    let provisioning = apply(
        new_wallet_lifecycle(identifier("provisioning-wallet")?, timestamp(1)?),
        WalletLifecycleEvent::BeginProvisioning,
        2,
    )?;
    let suspended = apply(active.clone(), WalletLifecycleEvent::Suspend, 4)?;
    let recovering = apply(active.clone(), WalletLifecycleEvent::BeginRecovery, 4)?;
    let migrating = apply(active.clone(), WalletLifecycleEvent::BeginMigration, 4)?;
    let withdrawing = apply(active.clone(), WalletLifecycleEvent::BeginWithdrawal, 4)?;
    let deleting = apply(active.clone(), WalletLifecycleEvent::BeginDeletion, 4)?;
    let failed = apply(recovering.clone(), WalletLifecycleEvent::MarkFailed, 5)?;
    let withdrawn = apply(
        withdrawing.clone(),
        WalletLifecycleEvent::CompleteWithdrawal,
        5,
    )?;
    let deleted = apply(deleting.clone(), WalletLifecycleEvent::CompleteDeletion, 5)?;
    let unprovisioned = new_wallet_lifecycle(identifier("unprovisioned-wallet")?, timestamp(1)?);

    let blocked_records = [
        unprovisioned,
        provisioning,
        suspended,
        recovering,
        migrating,
        withdrawing,
        deleting,
        failed,
        withdrawn,
        deleted,
    ];
    let regulated_operations = [
        WalletOperation::BeginIssuance,
        WalletOperation::PresentCredential,
        WalletOperation::SignWithWalletKey,
        WalletOperation::RenewAttestation,
    ];
    for record in blocked_records {
        for operation in regulated_operations {
            assert!(ensure_wallet_operation_allowed(&record, operation).is_err());
        }
    }
    for operation in regulated_operations {
        assert!(ensure_wallet_operation_allowed(&active, operation).is_ok());
    }
    Ok(())
}

#[test]
fn restored_state_must_match_its_evidence_provenance() -> Result<(), ProbeError> {
    let active = active_record()?;
    let deletion_time = timestamp(5)?;
    let deletion_evidence = WalletLifecycleEvidenceRecord {
        id: identifier("deletion-evidence")?,
        wallet_instance_id: active.wallet_instance_id().clone(),
        kind: WalletLifecycleEvidenceKind::Deletion,
        event: WalletLifecycleEvent::CompleteDeletion,
        occurred_at: deletion_time,
        authority_id: identifier("framework-authority")?,
        evidence_ref: identifier("framework-reference")?,
        evidence_digest: vec![0x62; 32],
    };
    assert!(matches!(
        restore_wallet_lifecycle(
            active.wallet_instance_id().clone(),
            WalletLifecycleState::Active,
            deletion_time,
            Some(WalletLifecycleEvent::CompleteDeletion),
            None,
            None,
            Some(deletion_evidence.clone()),
        ),
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
    ));

    let mut wrong_wallet_evidence = deletion_evidence.clone();
    wrong_wallet_evidence.wallet_instance_id = identifier("another-wallet")?;
    assert!(matches!(
        restore_wallet_lifecycle(
            active.wallet_instance_id().clone(),
            WalletLifecycleState::Deleted,
            deletion_time,
            Some(WalletLifecycleEvent::CompleteDeletion),
            None,
            None,
            Some(wrong_wallet_evidence),
        ),
        Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence
    ));

    let recovery_time = timestamp(6)?;
    let recovery_evidence = WalletLifecycleEvidenceRecord {
        id: identifier("recovery-evidence")?,
        wallet_instance_id: active.wallet_instance_id().clone(),
        kind: WalletLifecycleEvidenceKind::Recovery,
        event: WalletLifecycleEvent::BeginRecovery,
        occurred_at: recovery_time,
        authority_id: identifier("framework-authority")?,
        evidence_ref: identifier("framework-reference")?,
        evidence_digest: vec![0x63; 32],
    };
    assert!(matches!(
        restore_wallet_lifecycle(
            active.wallet_instance_id().clone(),
            WalletLifecycleState::RecoveryPending,
            recovery_time,
            Some(WalletLifecycleEvent::BeginRecovery),
            None,
            None,
            Some(recovery_evidence),
        ),
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
    ));
    Ok(())
}

#[test]
fn rollback_missing_evidence_and_invalid_successors_are_rejected() -> Result<(), ProbeError> {
    let active = active_record()?;
    assert!(matches!(
        apply_wallet_lifecycle_event(
            active.clone(),
            WalletLifecycleEvent::Suspend,
            timestamp(2)?,
            None,
        ),
        Err(error) if error.reason == LifecycleErrorReason::ClockRollback
    ));
    assert!(matches!(
        apply_wallet_lifecycle_event(
            active.clone(),
            WalletLifecycleEvent::Suspend,
            timestamp(4)?,
            None,
        ),
        Err(error) if error.reason == LifecycleErrorReason::InvalidEvidence
    ));

    let at = timestamp(4)?;
    let suspend_evidence = evidence(&active, WalletLifecycleEvent::Suspend, at)?;
    let suspended = apply_wallet_lifecycle_event(
        active.clone(),
        WalletLifecycleEvent::Suspend,
        at,
        Some(&suspend_evidence),
    )?;
    assert!(validate_wallet_lifecycle_successor(&active, &suspended, &suspend_evidence).is_ok());

    let wrong_evidence = evidence(&active, WalletLifecycleEvent::BeginDeletion, at)?;
    assert!(matches!(
        validate_wallet_lifecycle_successor(&active, &suspended, &wrong_evidence),
        Err(error) if error.reason == LifecycleErrorReason::InvalidTransition
            || error.reason == LifecycleErrorReason::InvalidEvidence
    ));
    Ok(())
}
