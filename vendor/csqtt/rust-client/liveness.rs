// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use anyhow::{Result, anyhow};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

const PROBE_INTERVAL: Duration = Duration::from_secs(60);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MISSED_RESPONSES: usize = 3;
const IDLE: u8 = 0;
const PENDING: u8 = 1;
const ACKNOWLEDGED: u8 = 2;
const REQUEST: &[u8] = b"READY";
const RESPONSE: &[u8] = b"READY_OK";

/// One instance belongs to one allocation's authenticated reader and writer.
/// The upstream exchange has no echoed nonce, so only one probe is outstanding.
pub(crate) struct PeerLiveness {
    phase: AtomicU8,
    changed: Notify,
}

impl PeerLiveness {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            phase: AtomicU8::new(IDLE),
            changed: Notify::new(),
        })
    }

    /// Call only for a packet accepted by the allocation's authenticated reader.
    pub(crate) fn observe_response(&self, payload: &[u8]) {
        if payload == RESPONSE
            && self
                .phase
                .compare_exchange(PENDING, ACKNOWLEDGED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            crate::daemon::liveness_event("reply");
            self.changed.notify_one();
        }
    }

    async fn acknowledged(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.phase.load(Ordering::Acquire) == ACKNOWLEDGED {
                return;
            }
            notified.await;
        }
    }
}

struct PendingProbe<'a>(&'a PeerLiveness);

impl<'a> PendingProbe<'a> {
    fn begin(state: &'a PeerLiveness) -> Result<Self> {
        state
            .phase
            .compare_exchange(IDLE, PENDING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow!("peer liveness probe already pending"))?;
        Ok(Self(state))
    }
}

impl Drop for PendingProbe<'_> {
    fn drop(&mut self) {
        self.0.phase.store(IDLE, Ordering::Release);
    }
}

#[derive(Debug)]
pub(crate) struct PeerLivenessTimeout;

impl std::fmt::Display for PeerLivenessTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PEER_LIVENESS_TIMEOUT: three READY responses missed")
    }
}

impl std::error::Error for PeerLivenessTimeout {}

pub(crate) async fn supervise<F, Fut>(
    state: Arc<PeerLiveness>,
    cancel: &CancellationToken,
    mut send: F,
) -> Result<()>
where
    F: FnMut(&'static [u8]) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut timer = tokio::time::interval_at(
        tokio::time::Instant::now() + PROBE_INTERVAL,
        PROBE_INTERVAL,
    );
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut missed = 0usize;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            _ = timer.tick() => {}
        }
        // Arm before handing the request to the writer, including an immediate reply.
        let _pending = PendingProbe::begin(&state)?;
        crate::daemon::liveness_event("probe");
        let attempt = async {
            send(REQUEST).await?;
            state.acknowledged().await;
            Ok::<(), anyhow::Error>(())
        };
        let answered = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            result = tokio::time::timeout(RESPONSE_TIMEOUT, attempt) => match result {
                Ok(result) => {
                    result?;
                    true
                }
                Err(_) => false,
            },
        };
        if answered {
            missed = 0;
        } else {
            crate::daemon::liveness_event("miss");
            missed += 1;
            if missed == MAX_MISSED_RESPONSES {
                crate::daemon::liveness_event("timeout");
                return Err(PeerLivenessTimeout.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::mpsc;

    struct FakePeer {
        state: Arc<PeerLiveness>,
        cancel: CancellationToken,
        requests: mpsc::Receiver<&'static [u8]>,
        task: tokio::task::JoinHandle<Result<()>>,
    }

    impl FakePeer {
        fn new() -> Self {
            let state = PeerLiveness::new();
            let cancel = CancellationToken::new();
            let (sender, requests) = mpsc::channel(8);
            let task_state = state.clone();
            let task_cancel = cancel.clone();
            let task = tokio::spawn(async move {
                supervise(task_state, &task_cancel, |request| {
                    let sender = sender.clone();
                    async move {
                        sender
                            .send(request)
                            .await
                            .map_err(|_| anyhow!("fake peer closed"))
                    }
                })
                .await
            });
            Self {
                state,
                cancel,
                requests,
                task,
            }
        }

        async fn request(&mut self) {
            assert_eq!(self.requests.recv().await, Some(REQUEST));
        }

        async fn stop(self) {
            self.cancel.cancel();
            assert!(self.task.await.unwrap().is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_peer_is_probed_after_one_minute_without_client_data() {
        let mut peer = FakePeer::new();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(peer.requests.try_recv().is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        peer.request().await;
        peer.state.observe_response(RESPONSE);
        peer.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn silent_peer_fails_after_three_bounded_attempts() {
        let mut peer = FakePeer::new();
        let started = tokio::time::Instant::now();
        for _ in 0..3 {
            peer.request().await;
        }
        let error = peer.task.await.unwrap().unwrap_err();
        assert!(error.downcast_ref::<PeerLivenessTimeout>().is_some());
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_secs(185)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_reply_during_writer_send_is_not_lost() {
        let state = PeerLiveness::new();
        let cancel = CancellationToken::new();
        let sends = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            let sends = sends.clone();
            async move {
                supervise(state.clone(), &cancel, |request| {
                    assert_eq!(request, REQUEST);
                    state.observe_response(RESPONSE);
                    sends.fetch_add(1, Ordering::AcqRel);
                    async { Ok(()) }
                }).await
            }
        });
        tokio::task::yield_now().await;
        for _ in 0..5 {
            tokio::time::advance(PROBE_INTERVAL).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(sends.load(Ordering::Acquire), 5);
        assert!(!task.is_finished());
        cancel.cancel();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn timely_success_resets_the_consecutive_failure_count() {
        let mut peer = FakePeer::new();
        for attempt in 0..7 {
            peer.request().await;
            if attempt % 3 == 2 {
                peer.state.observe_response(RESPONSE);
                tokio::task::yield_now().await;
            }
        }
        assert!(!peer.task.is_finished());
        peer.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn late_and_unsolicited_replies_do_not_pre_acknowledge_the_next_probe() {
        let mut peer = FakePeer::new();
        peer.state.observe_response(RESPONSE);
        for _ in 0..3 {
            peer.request().await;
            tokio::time::advance(RESPONSE_TIMEOUT).await;
            tokio::task::yield_now().await;
            peer.state.observe_response(RESPONSE);
        }
        assert!(peer.task.await.unwrap().unwrap_err().downcast_ref::<PeerLivenessTimeout>().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn unrelated_control_data_and_malformed_acknowledgements_do_not_hide_silence() {
        let mut peer = FakePeer::new();
        for _ in 0..3 {
            peer.request().await;
            for packet in [
                b"READY_OKextra".as_slice(),
                b"READY_O",
                b"NOCONF",
                b"TUNCONF:10.0.0.2",
                b"\xffCSQTT_STREAM_ALIVE_V1",
                b"payload",
                b"\xff",
                b"",
            ] {
                peer.state.observe_response(packet);
            }
        }
        assert!(peer.task.await.unwrap().unwrap_err().downcast_ref::<PeerLivenessTimeout>().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn previous_allocation_responses_cannot_acknowledge_a_new_session() {
        let mut old_peer = FakePeer::new();
        old_peer.request().await;
        let old_reader = old_peer.state.clone();
        old_peer.stop().await;
        let mut new_peer = FakePeer::new();
        for _ in 0..3 {
            new_peer.request().await;
            old_reader.observe_response(RESPONSE);
        }
        assert!(new_peer.task.await.unwrap().unwrap_err().downcast_ref::<PeerLivenessTimeout>().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_is_immediate_while_idle_or_waiting_for_a_response() {
        let peer = FakePeer::new();
        let before = tokio::time::Instant::now();
        peer.stop().await;
        assert_eq!(tokio::time::Instant::now(), before);

        let mut peer = FakePeer::new();
        peer.request().await;
        let before = tokio::time::Instant::now();
        peer.stop().await;
        assert_eq!(tokio::time::Instant::now(), before);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_writer_is_bounded_by_the_same_three_attempt_limit() {
        let state = PeerLiveness::new();
        let cancel = CancellationToken::new();
        let sends = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            let sends = sends.clone();
            async move {
                supervise(state, &cancel, |_| {
                    sends.fetch_add(1, Ordering::AcqRel);
                    std::future::pending::<Result<()>>()
                }).await
            }
        });
        let error = task.await.unwrap().unwrap_err();
        assert!(error.downcast_ref::<PeerLivenessTimeout>().is_some());
        assert_eq!(sends.load(Ordering::Acquire), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_drops_a_pending_writer_send_without_waiting_for_its_deadline() {
        struct SendDropped(Arc<AtomicUsize>);
        impl Drop for SendDropped {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let state = PeerLiveness::new();
        let cancel = CancellationToken::new();
        let dropped = Arc::new(AtomicUsize::new(0));
        let (started_tx, mut started_rx) = mpsc::channel(1);
        let task = tokio::spawn({
            let cancel = cancel.clone();
            let dropped = dropped.clone();
            async move {
                supervise(state, &cancel, |_| {
                    let sender = started_tx.clone();
                    let dropped = dropped.clone();
                    async move {
                        let _drop = SendDropped(dropped);
                        sender.send(()).await.unwrap();
                        std::future::pending::<Result<()>>().await
                    }
                }).await
            }
        });
        started_rx.recv().await.unwrap();
        let before = tokio::time::Instant::now();
        cancel.cancel();
        task.await.unwrap().unwrap();
        assert_eq!(tokio::time::Instant::now(), before);
        assert_eq!(dropped.load(Ordering::Acquire), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_send_and_aborted_probe_release_state_for_a_new_supervisor() {
        let state = PeerLiveness::new();
        let cancel = CancellationToken::new();
        let error = supervise(state.clone(), &cancel, |_| async { Err(anyhow!("send failed")) })
            .await.unwrap_err();
        assert_eq!(error.to_string(), "send failed");
        let task = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            async move {
                supervise(state, &cancel, |_| std::future::pending::<Result<()>>()).await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(PROBE_INTERVAL).await;
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let task = tokio::spawn({
            let state = state.clone();
            let cancel = cancel.clone();
            async move {
                supervise(state.clone(), &cancel, |_| {
                    state.observe_response(RESPONSE);
                    async { Ok(()) }
                }).await
            }
        });
        tokio::task::yield_now().await;
        tokio::time::advance(PROBE_INTERVAL).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        cancel.cancel();
        task.await.unwrap().unwrap();
    }
}
