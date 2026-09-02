//! Deterministic advisory state for currently visible discovered peers.

use std::collections::HashMap;
use std::time::Duration;

use crate::browser::{
    DiscoveredPeer, DiscoveryBrowserError, DiscoveryBrowserEvent, TransientDiscoveryKey,
};

/// Maximum absent advertisement keys retained to reject late lifecycle input.
const MAX_RETAINED_TOMBSTONES: usize = 256;
/// Caller-time horizon for retaining an absent advertisement key.
const TOMBSTONE_RETENTION: Duration = Duration::from_secs(300);

/// One currently visible, unauthenticated discovery snapshot and its liveness time.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VisibleDiscoveredPeer {
    peer: DiscoveredPeer,
    last_observed_at: Duration,
}

/// Why a currently visible advertisement left discovery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveredPeerRemovalReason {
    /// The discovery adapter explicitly reported removal.
    Explicit,
    /// The caller expired the advertisement after its liveness window elapsed.
    Expired,
}

/// Why a lifecycle input produced no state change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveredPeerNoopReason {
    /// The advertisement was already absent.
    AlreadyAbsent,
    /// The input predates the latest transition retained for this advertisement.
    Stale,
}

/// The explicit result of applying one discovery lifecycle input.
#[derive(Debug)]
pub enum DiscoveredPeerTransition {
    /// A valid compatible advertisement became visible.
    Appeared(TransientDiscoveryKey),
    /// An equivalent valid observation refreshed liveness only.
    Refreshed(TransientDiscoveryKey),
    /// A valid observation meaningfully changed the visible snapshot.
    Updated(TransientDiscoveryKey),
    /// A visible advertisement was removed.
    Removed {
        /// The affected transient advertisement key.
        key: TransientDiscoveryKey,
        /// The reason it left visible state.
        reason: DiscoveredPeerRemovalReason,
    },
    /// A valid lifecycle input intentionally had no effect.
    Noop {
        /// The affected transient advertisement key.
        key: TransientDiscoveryKey,
        /// Why state did not change.
        reason: DiscoveredPeerNoopReason,
    },
    /// Browser validation or infrastructure rejected an observation before state mutation.
    Rejected(DiscoveryBrowserError),
}

#[derive(Debug)]
struct PeerRecord {
    visible: Option<VisibleDiscoveredPeer>,
    last_transition_at: Duration,
}

/// Portable state for bounded, compatible, unauthenticated discovery snapshots.
///
/// Times are durations on a caller-owned monotonic timeline. The state reads no
/// clock and schedules no work. Recent absent records are retained as bounded
/// tombstones so late observations cannot undo a newer removal or expiry.
#[derive(Debug, Default)]
pub struct DiscoveredPeerState {
    records: HashMap<TransientDiscoveryKey, PeerRecord>,
    visible_count: usize,
}

impl DiscoveredPeerState {
    /// Creates empty discovery lifecycle state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of currently visible advertisements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.visible_count
    }

    /// Reports whether no advertisements are currently visible.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.visible_count == 0
    }

    /// Returns a visible advertisement by its transient session key.
    #[must_use]
    pub fn get(&self, key: &TransientDiscoveryKey) -> Option<&DiscoveredPeer> {
        self.records
            .get(key)?
            .visible
            .as_ref()
            .map(|visible| &visible.peer)
    }

    /// Iterates over currently visible advertisements in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = &DiscoveredPeer> {
        self.records
            .values()
            .filter_map(|record| record.visible.as_ref().map(|visible| &visible.peer))
    }

    /// Applies one validated browser event at an explicit caller-supplied time.
    ///
    /// Rejected browser events never create, mutate, or refresh visible state.
    pub fn apply(
        &mut self,
        event: DiscoveryBrowserEvent,
        observed_at: Duration,
    ) -> DiscoveredPeerTransition {
        match event {
            DiscoveryBrowserEvent::Added(peer)
            | DiscoveryBrowserEvent::Updated(peer)
            | DiscoveryBrowserEvent::Refreshed(peer) => {
                self.prune_tombstones(observed_at);
                self.observe(peer, observed_at)
            }
            DiscoveryBrowserEvent::Removed(key) => {
                self.prune_tombstones(observed_at);
                let transition = self.remove(key, observed_at);
                self.prune_tombstones(observed_at);
                transition
            }
            DiscoveryBrowserEvent::Error(error) => DiscoveredPeerTransition::Rejected(error),
        }
    }

    /// Expires every visible advertisement at least `stale_after` old.
    ///
    /// Returned transitions are sorted by transient key for deterministic callers.
    pub fn expire(
        &mut self,
        now: Duration,
        stale_after: Duration,
    ) -> Vec<DiscoveredPeerTransition> {
        self.prune_tombstones(now);
        let mut expired: Vec<_> = self
            .records
            .iter()
            .filter_map(|(key, record)| {
                let visible = record.visible.as_ref()?;
                (now >= visible.last_observed_at
                    && now.saturating_sub(visible.last_observed_at) >= stale_after)
                    .then(|| key.clone())
            })
            .collect();
        expired.sort();

        let transitions = expired
            .into_iter()
            .map(|key| {
                let record = self
                    .records
                    .get_mut(&key)
                    .expect("expiry keys originate from existing records");
                record.visible = None;
                record.last_transition_at = now;
                self.visible_count -= 1;
                DiscoveredPeerTransition::Removed {
                    key,
                    reason: DiscoveredPeerRemovalReason::Expired,
                }
            })
            .collect();
        self.prune_tombstones(now);
        transitions
    }

    fn observe(&mut self, peer: DiscoveredPeer, observed_at: Duration) -> DiscoveredPeerTransition {
        let key = peer.key().clone();
        match self.records.get_mut(&key) {
            Some(record) if observed_at < record.last_transition_at => {
                DiscoveredPeerTransition::Noop {
                    key,
                    reason: DiscoveredPeerNoopReason::Stale,
                }
            }
            Some(record)
                if record.visible.is_none() && observed_at == record.last_transition_at =>
            {
                DiscoveredPeerTransition::Noop {
                    key,
                    reason: DiscoveredPeerNoopReason::Stale,
                }
            }
            Some(record) => {
                let transition = match record.visible.as_ref() {
                    Some(visible) if visible.peer == peer => {
                        DiscoveredPeerTransition::Refreshed(key.clone())
                    }
                    Some(_) => DiscoveredPeerTransition::Updated(key.clone()),
                    None => {
                        self.visible_count += 1;
                        DiscoveredPeerTransition::Appeared(key.clone())
                    }
                };
                record.visible = Some(VisibleDiscoveredPeer {
                    peer,
                    last_observed_at: observed_at,
                });
                record.last_transition_at = observed_at;
                transition
            }
            None => {
                self.records.insert(
                    key.clone(),
                    PeerRecord {
                        visible: Some(VisibleDiscoveredPeer {
                            peer,
                            last_observed_at: observed_at,
                        }),
                        last_transition_at: observed_at,
                    },
                );
                self.visible_count += 1;
                DiscoveredPeerTransition::Appeared(key)
            }
        }
    }

    fn remove(
        &mut self,
        key: TransientDiscoveryKey,
        removed_at: Duration,
    ) -> DiscoveredPeerTransition {
        match self.records.get_mut(&key) {
            Some(record) if removed_at < record.last_transition_at => {
                DiscoveredPeerTransition::Noop {
                    key,
                    reason: DiscoveredPeerNoopReason::Stale,
                }
            }
            Some(record) if record.visible.is_some() => {
                record.visible = None;
                record.last_transition_at = removed_at;
                self.visible_count -= 1;
                DiscoveredPeerTransition::Removed {
                    key,
                    reason: DiscoveredPeerRemovalReason::Explicit,
                }
            }
            Some(record) => {
                record.last_transition_at = record.last_transition_at.max(removed_at);
                DiscoveredPeerTransition::Noop {
                    key,
                    reason: DiscoveredPeerNoopReason::AlreadyAbsent,
                }
            }
            None => {
                self.records.insert(
                    key.clone(),
                    PeerRecord {
                        visible: None,
                        last_transition_at: removed_at,
                    },
                );
                DiscoveredPeerTransition::Noop {
                    key,
                    reason: DiscoveredPeerNoopReason::AlreadyAbsent,
                }
            }
        }
    }

    fn prune_tombstones(&mut self, now: Duration) {
        self.records.retain(|_, record| {
            record.visible.is_some()
                || now < record.last_transition_at
                || now.saturating_sub(record.last_transition_at) <= TOMBSTONE_RETENTION
        });

        let mut tombstones: Vec<_> = self
            .records
            .iter()
            .filter(|(_, record)| record.visible.is_none())
            .map(|(key, record)| (record.last_transition_at, key.clone()))
            .collect();
        if tombstones.len() <= MAX_RETAINED_TOMBSTONES {
            return;
        }
        tombstones.sort();
        let excess = tombstones.len() - MAX_RETAINED_TOMBSTONES;
        for (_, key) in tombstones.into_iter().take(excess) {
            self.records.remove(&key);
        }
    }

    #[cfg(test)]
    fn tombstone_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| record.visible.is_none())
            .count()
    }

    #[cfg(test)]
    fn last_observed_at(&self, key: &TransientDiscoveryKey) -> Option<Duration> {
        self.records
            .get(key)?
            .visible
            .as_ref()
            .map(|visible| visible.last_observed_at)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::num::NonZeroU16;

    use super::*;
    use crate::browser::{DiscoveryBrowserErrorKind, DiscoveryEndpoint};
    use crate::discovery::{
        DiscoveryMetadata, DiscoveryNameHint, DiscoveryPlatformHint, DiscoveryProtocolRange,
    };

    const KEY_A: &str = "peer-a._local-transfer._tcp.local.";
    const KEY_B: &str = "peer-b._local-transfer._tcp.local.";

    fn time(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn key(value: &str) -> TransientDiscoveryKey {
        TransientDiscoveryKey::new(value).unwrap()
    }

    fn peer(key_value: &str, name: &str, address_last_octet: u8) -> DiscoveredPeer {
        DiscoveredPeer::for_test(
            key(key_value),
            DiscoveryMetadata::new(
                DiscoveryProtocolRange::initial(),
                Some(DiscoveryNameHint::new(name).unwrap()),
                Some(DiscoveryPlatformHint::Linux),
            ),
            NonZeroU16::new(4242).unwrap(),
            vec![DiscoveryEndpoint::ipv4(Ipv4Addr::new(
                192,
                0,
                2,
                address_last_octet,
            ))],
            1,
        )
    }

    fn assert_noop(transition: DiscoveredPeerTransition, expected: DiscoveredPeerNoopReason) {
        assert!(matches!(
            transition,
            DiscoveredPeerTransition::Noop {
                reason,
                ..
            } if reason == expected
        ));
    }

    #[test]
    fn first_observation_appears_without_trust_or_identity_state() {
        let mut state = DiscoveredPeerState::new();

        let transition = state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(1),
        );

        assert!(matches!(transition, DiscoveredPeerTransition::Appeared(_)));
        assert_eq!(state.len(), 1);
        let visible = state.get(&key(KEY_A)).unwrap();
        assert_eq!(visible.key().as_str(), KEY_A);
        assert_eq!(state.last_observed_at(&key(KEY_A)), Some(time(1)));
    }

    #[test]
    fn equivalent_observations_refresh_liveness_without_duplicates() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(1),
        );

        let transition = state.apply(
            DiscoveryBrowserEvent::Refreshed(peer(KEY_A, "Desk", 1)),
            time(4),
        );

        assert!(matches!(transition, DiscoveredPeerTransition::Refreshed(_)));
        assert_eq!(state.len(), 1);
        assert_eq!(state.iter().count(), 1);
        assert_eq!(state.last_observed_at(&key(KEY_A)), Some(time(4)));
    }

    #[test]
    fn meaningful_observation_updates_existing_peer() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(1),
        );

        let transition = state.apply(
            DiscoveryBrowserEvent::Updated(peer(KEY_A, "Kitchen", 2)),
            time(2),
        );

        assert!(matches!(transition, DiscoveredPeerTransition::Updated(_)));
        assert_eq!(state.len(), 1);
        let visible = state.get(&key(KEY_A)).unwrap();
        assert_eq!(visible.metadata().name().unwrap().as_str(), "Kitchen");
        assert_eq!(
            visible.endpoints()[0].address(),
            Ipv4Addr::new(192, 0, 2, 2)
        );
    }

    #[test]
    fn expiry_is_explicit_deterministic_and_idempotent() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(2),
        );

        assert!(state.expire(time(6), time(5)).is_empty());
        let expired = state.expire(time(7), time(5));
        assert!(matches!(
            expired.as_slice(),
            [DiscoveredPeerTransition::Removed {
                reason: DiscoveredPeerRemovalReason::Expired,
                ..
            }]
        ));
        assert!(state.is_empty());
        assert!(state.expire(time(20), time(5)).is_empty());
    }

    #[test]
    fn explicit_and_duplicate_removal_have_distinct_outcomes() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(1),
        );

        let removed = state.apply(DiscoveryBrowserEvent::Removed(key(KEY_A)), time(2));
        assert!(matches!(
            removed,
            DiscoveredPeerTransition::Removed {
                reason: DiscoveredPeerRemovalReason::Explicit,
                ..
            }
        ));
        assert_noop(
            state.apply(DiscoveryBrowserEvent::Removed(key(KEY_A)), time(3)),
            DiscoveredPeerNoopReason::AlreadyAbsent,
        );
        assert!(state.expire(time(20), time(1)).is_empty());
    }

    #[test]
    fn stale_events_cannot_undo_newer_lifecycle_state() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(5),
        );
        state.apply(DiscoveryBrowserEvent::Removed(key(KEY_A)), time(8));

        assert_noop(
            state.apply(
                DiscoveryBrowserEvent::Added(peer(KEY_A, "Late", 2)),
                time(7),
            ),
            DiscoveredPeerNoopReason::Stale,
        );
        assert_noop(
            state.apply(
                DiscoveryBrowserEvent::Added(peer(KEY_A, "Same", 2)),
                time(8),
            ),
            DiscoveredPeerNoopReason::Stale,
        );
        assert!(state.is_empty());

        assert!(matches!(
            state.apply(
                DiscoveryBrowserEvent::Added(peer(KEY_A, "Back", 2)),
                time(9)
            ),
            DiscoveredPeerTransition::Appeared(_)
        ));
    }

    #[test]
    fn observations_at_or_before_expiry_do_not_restore_visibility() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(1),
        );
        state.expire(time(6), time(5));

        assert_noop(
            state.apply(
                DiscoveryBrowserEvent::Refreshed(peer(KEY_A, "Desk", 1)),
                time(5),
            ),
            DiscoveredPeerNoopReason::Stale,
        );
        assert_noop(
            state.apply(
                DiscoveryBrowserEvent::Refreshed(peer(KEY_A, "Desk", 1)),
                time(6),
            ),
            DiscoveredPeerNoopReason::Stale,
        );
        assert!(state.is_empty());
    }

    #[test]
    fn tombstones_expire_without_mutating_unrelated_visible_peers() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Visible", 1)),
            time(1),
        );
        state.apply(DiscoveryBrowserEvent::Removed(key(KEY_B)), time(1));
        assert_eq!(state.tombstone_count(), 1);

        state.expire(time(1) + TOMBSTONE_RETENTION + time(1), time(10_000));

        assert_eq!(state.tombstone_count(), 0);
        assert_eq!(state.len(), 1);
        assert!(state.get(&key(KEY_A)).is_some());
    }

    #[test]
    fn observation_after_tombstone_retention_can_reappear() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(1),
        );
        state.apply(DiscoveryBrowserEvent::Removed(key(KEY_A)), time(2));

        let transition = state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(2) + TOMBSTONE_RETENTION + time(1),
        );

        assert!(matches!(transition, DiscoveredPeerTransition::Appeared(_)));
        assert_eq!(state.len(), 1);
        assert_eq!(state.tombstone_count(), 0);
    }

    #[test]
    fn capacity_pressure_evicts_oldest_tombstones_and_allows_reappearance() {
        let mut state = DiscoveredPeerState::new();
        let churn_count = MAX_RETAINED_TOMBSTONES + 100;

        for index in 0..churn_count {
            let transient = key(&format!("churn-{index:04}._local-transfer._tcp.local."));
            state.apply(DiscoveryBrowserEvent::Removed(transient), time(1));
        }

        assert_eq!(state.tombstone_count(), MAX_RETAINED_TOMBSTONES);
        let evicted_key = "churn-0000._local-transfer._tcp.local.";
        assert!(matches!(
            state.apply(
                DiscoveryBrowserEvent::Added(peer(evicted_key, "Reappeared", 3)),
                time(1),
            ),
            DiscoveredPeerTransition::Appeared(_)
        ));
        let retained_key = format!("churn-{:04}._local-transfer._tcp.local.", churn_count - 1);
        assert_noop(
            state.apply(
                DiscoveryBrowserEvent::Added(peer(&retained_key, "Still stale", 4)),
                time(1),
            ),
            DiscoveredPeerNoopReason::Stale,
        );
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn rejected_observations_never_enter_or_refresh_state() {
        let mut state = DiscoveredPeerState::new();
        state.apply(
            DiscoveryBrowserEvent::Added(peer(KEY_A, "Desk", 1)),
            time(2),
        );

        let error = TransientDiscoveryKey::new("invalid").unwrap_err();
        assert_eq!(error.kind(), DiscoveryBrowserErrorKind::InvalidTransientKey);
        assert!(matches!(
            state.apply(DiscoveryBrowserEvent::Error(error), time(10)),
            DiscoveredPeerTransition::Rejected(_)
        ));
        assert_eq!(state.len(), 1);
        assert_eq!(state.last_observed_at(&key(KEY_A)), Some(time(2)));

        let mut empty = DiscoveredPeerState::new();
        let error = TransientDiscoveryKey::new("invalid").unwrap_err();
        assert!(matches!(
            empty.apply(DiscoveryBrowserEvent::Error(error), time(1)),
            DiscoveredPeerTransition::Rejected(_)
        ));
        assert!(empty.is_empty());
    }

    #[test]
    fn peer_transitions_are_isolated_and_expiry_order_is_stable() {
        let mut state = DiscoveredPeerState::new();
        state.apply(DiscoveryBrowserEvent::Added(peer(KEY_B, "B", 2)), time(1));
        state.apply(DiscoveryBrowserEvent::Added(peer(KEY_A, "A", 1)), time(1));
        state.apply(
            DiscoveryBrowserEvent::Refreshed(peer(KEY_A, "A", 1)),
            time(5),
        );

        let expired = state.expire(time(6), time(5));
        assert_eq!(expired.len(), 1);
        assert!(matches!(
            &expired[0],
            DiscoveredPeerTransition::Removed { key, .. } if key.as_str() == KEY_B
        ));
        assert!(state.get(&key(KEY_A)).is_some());
        assert!(state.get(&key(KEY_B)).is_none());
    }
}
