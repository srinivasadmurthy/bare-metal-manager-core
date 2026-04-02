/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::io;
use std::sync::Arc;

use std::collections::HashMap;

use carbide_uuid::machine::MachineId;

use db::dpa_interface::get_dpa_vni;
use chrono::TimeDelta;
use crate::dpa::handler::DpaInfo;
use db::db_read::PgPoolReader;
use crate::periodic_timer::PeriodicTimer;
use db::work_lock_manager::WorkLockManagerHandle;
use db::{self};
use sqlx::{PgConnection, PgPool, PgTransaction};
use std::time::Duration;
use model::dpa_interface::{DpaInterface, DpaInterfaceControllerState};

use crate::{CarbideResult, CarbideError};
use crate::api::TransactionVending;
use crate::cfg::file::DpaConfig;
use mqttea::client::MqtteaClient;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use model::machine::{HostHealthConfig, LoadSnapshotOptions, ManagedHostStateSnapshot};
use model::machine::machine_search_config::MachineSearchConfig;

use metrics::{DpaMonitorMetrics};

use chrono::Utc;
use tracing::Instrument;

mod metrics;

#[allow(dead_code)]
pub struct DpaMonitor {
    db_services: DbServices,
    dpa_info: Option<Arc<DpaInfo>>,
    config: DpaConfig,
    host_health: HostHealthConfig,
    metric_holder: Arc<metrics::MetricHolder>,
    work_lock_manager_handle: WorkLockManagerHandle,
    last_dpa_info_validation: std::sync::Mutex<Option<std::time::Instant>>,
}

pub struct DbServices {
    db_pool: PgPool,
    db_reader: PgPoolReader,
}

// This carries the result running the handler for a single dpa interface.
// If the dpa interface needs to a new state, the new state is returned.
// If we started a transaction in the handler, the transaction is returned.
pub struct HandlerResult {
    new_state: Option<DpaInterfaceControllerState>,
    txn: Option<PgTransaction<'static>>,
}

impl DpaMonitor {
    const ITERATION_WORK_KEY: &'static str = "DpaMonitor::run_single_iteration";

   

    pub fn new(
        db_pool: PgPool,
        db_reader: PgPoolReader,
        dpa_info: Option<Arc<DpaInfo>>,
        _meter: opentelemetry::metrics::Meter,
        config: DpaConfig,
        host_health: HostHealthConfig,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        let hold_period = config
            .monitor_run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(_meter, hold_period));

        Self {
            db_services: DbServices {
                db_pool: db_pool,
                db_reader: db_reader,
            },
            dpa_info: dpa_info,
            config: config,
            host_health: host_health,
            work_lock_manager_handle: work_lock_manager_handle,
            last_dpa_info_validation: std::sync::Mutex::new(None),
            metric_holder: metric_holder,
        }
    }

    pub fn start(
        mut self,
        join_set: &mut JoinSet<()>,
        cancel_token: CancellationToken,
    ) -> io::Result<()> {

        println!("{} SDM dpa monitor start enabled: {}", Utc::now(), self.config.enabled);

        if self.config.enabled {
            join_set
                .build_task()
                .name("dpa-monitor")
                .spawn(async move { self.run(cancel_token).await })?;
        }

        Ok(())
    }

    pub async fn run(&mut self, cancel_token: CancellationToken) {
        let timer = PeriodicTimer::new(self.config.monitor_run_interval);
        loop {
            let mut tick = timer.tick();
            println!("{} SDM dpa monitor run", Utc::now());
            match self.run_single_iteration().await {
                Ok(num_changes) => {
                    if num_changes > 0 {
                        // Decrease the interval if changes have been made.
                        tick.set_interval(Duration::from_millis(1000));
                    }
                }
                Err(e) => {
                    tracing::warn!("DpaMonitor error: {}", e);
                }
            }

            tokio::select! {
                _ = tick.sleep() => {},
                _ = cancel_token.cancelled() => {
                    tracing::info!("DpaMonitor stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&mut self) -> CarbideResult<usize> {
        println!("{} SDM dpa monitor run_single_iteration", Utc::now());
        let mut metrics = DpaMonitorMetrics::new();
        let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));
        let check_dpa_span = tracing::span!(
            parent: None,
            tracing::Level::INFO,
            "dpa-monitor",
            span_id,
        );
        let result = self
            .run_single_iteration_inner(&mut metrics)
            .instrument(check_dpa_span.clone())
            .await;
        check_dpa_span.record("metrics", metrics.to_string());
        self.metric_holder.update_metrics(metrics);
        result
    }

    async fn run_single_iteration_inner(&mut self, metrics: &mut DpaMonitorMetrics) -> CarbideResult<usize> {
        println!("{} SDM dpa monitor run_single_iteration_inner", Utc::now());
        let _lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                tracing::warn!(
                    "DpaMonitor failed to acquire work lock: Another instance of carbide running? {e}"
                );
                return Ok(0);
            }
        };
        tracing::info!(
            lock = Self::ITERATION_WORK_KEY,
            "DpaMonitor acquired the lock",
        );

        let mut txn = self.db_services.db_pool.txn_begin().await?;

        let mut snapshots = match self.get_all_snapshots(&mut txn).await {
            Ok(snapshots) => snapshots,
            Err(e) => {
                tracing::error!(error = %e, "Failed to load ManagedHost snapshots in IbFabricMonitor");
                // Record the same error for all fabrics, so that the problem is at least visible on dashboards
                return Err(e);
            }
        };

        txn.commit().await?;

        println!("{} SDM dpa monitor run_single_iteration_inner: got {} snapshots", Utc::now(), snapshots.len());

        for mh in snapshots.values_mut() {
            metrics.num_machines_scanned += 1;

            // If the machine does not have any dpa interfaces, we can skip it.
            if mh.dpa_interface_snapshots.is_empty() {
                println!("{} SDM dpa monitor run_single_iteration_inner: skipping, no dpa interfaces", Utc::now());
                continue;
            }

            // If the machine is an instance, increment the number of instances scanned.
            if mh.instance.is_some() {
                metrics.num_instances_scanned += 1;
            }

            for idx in 0..mh.dpa_interface_snapshots.len() {
                metrics.num_dpa_interfaces_scanned += 1;

                let controller_state = mh.dpa_interface_snapshots[idx].controller_state.clone();

                // Look at this DPA interface and see if we need to transition it to a new state.
                // This will return a new state if we need to transition to a new state, or None if we can stay in the current state.
                // We build an array of dpa interfaces and new state.
                // After examining all the dpa interfaces in all the machines, we will update the DB with the new states in another loop
                let handler_result = self.handle_dpa_interface(mh, idx).await?;

                let new_state = handler_result.new_state;
                let txn = handler_result.txn;

                if let Some(new_state) = new_state {
                    let new_version = controller_state.version.increment();

                    let mut txn = match txn {
                        Some(t) => t,
                        None => self.db_services.db_pool.begin().await.map_err(|e| db::AnnotatedSqlxError::new("dpa_monitor begin txn", e))?,
                    };

                    db::dpa_interface::try_update_controller_state(
                        &mut txn,
                        mh.dpa_interface_snapshots[idx].id,
                        controller_state.version,
                        new_version,
                        &new_state,
                    )
                    .await?;

                    txn.commit().await.map_err(|e| db::AnnotatedSqlxError::new("dpa_monitor commit txn", e))?;
                } else if let Some(txn) = txn {
                    txn.commit().await.map_err(|e| db::AnnotatedSqlxError::new("dpa_monitor commit txn", e))?;
                }
            }
        }

        Ok(0)
    }

    // This should return a txn if we started one, an indication of whether state is changing,
    // and if so, the new state.
    // We should:
    //    1. Go through the state transitions for the card.
    //    2. Send heartbeats in Ready and Assigned states if necessary.
    //    3. If the DPA is in ASSIGNED state, go through the attachments.
    //    4.    If we are not an instance, then, we need to do ResetVNI.
    //    5.    If we are an instance, then, we need to do SetVNI.
    //    6. We need a way for machine statehandler to determine if congig is done.
    async fn handle_dpa_interface(
        &mut self,
        mh: &mut ManagedHostStateSnapshot,
        idx: usize,
    ) -> CarbideResult<HandlerResult> {
        let dpa_interface = &mut mh.dpa_interface_snapshots[idx];

        let in_instance = mh.instance.is_some();

        let hb_interval = self.config.hb_interval;

        let dpa_info = self.dpa_info.clone().unwrap();

        println!("{} SDM dpa monitor handle_dpa_interface: {}, in_instance: {}", Utc::now(), dpa_interface.id, in_instance);

        let controller_state = dpa_interface.controller_state.value.clone();
        match controller_state {
            DpaInterfaceControllerState::Provisioning => {
                if !in_instance {
                    println!("{} SDM dpa monitor handle_dpa_interface: skipping, not in instance", Utc::now());
                    return Ok(HandlerResult {
                        new_state: None,
                        txn: None,
                    });
                }

                let new_state = DpaInterfaceControllerState::Ready;
                tracing::info!(state = ?new_state, "Dpa Interface state transition");
                return Ok(HandlerResult {
                    new_state: Some(new_state),
                    txn: None,
                });
            }

            DpaInterfaceControllerState::Ready => {
                // We will stay in Ready state as long use_admin_network is true.
                // When an instance is created from this host, use_admin_network
                // will be turned off. We then need to SetVNI, and wait for the
                // SetVNI to take effect.

                let client = dpa_info
                    .mqtt_client
                    .clone()
                    .ok_or_else(|| eyre::eyre!("Missing mqtt_client"))?;

                if in_instance {
                    // We are in the process of transitioning to an instance.
                    // So go through the unlock/apply firmware/lock sequence
                    let new_state = DpaInterfaceControllerState::Unlocking;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");

                    return Ok(HandlerResult {
                        new_state: Some(new_state),
                        txn: None,
                    });
                } else {
                    // We are in the Ready state, and we are not an instane.
                    // So just do hearbeats
                    let txn =
                        do_heartbeat(dpa_interface, &mut self.db_services, client, &dpa_info, hb_interval, false)
                            .await?;

                    return Ok(HandlerResult {
                        new_state: None,
                        txn: txn,
                    });
                }
            }

            _ => {}
        }
        Ok(HandlerResult {
            new_state: None,
            txn: None,
        })
    }

    async fn get_all_snapshots(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashMap<MachineId, ManagedHostStateSnapshot>> {
        let machine_ids = db::machine::find_machine_ids(
            &mut *txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;

        let mut res = db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: true,
                host_health_config: self.host_health,
            },
        )
        .await
        .map_err(Into::<CarbideError>::into)?;

        for mh in res.values_mut() {
            let machine_id = mh.host_snapshot.id;
            let dpa_snapshots = db::dpa_interface::find_by_machine_id(&mut *txn, machine_id)
                .await
                .map_err(Into::<CarbideError>::into)?;
            mh.dpa_interface_snapshots = dpa_snapshots;
        }

        Ok(res)
    }
}

// Determine if we need to do a heartbeat or if we need to
// send a SetVni command because the DPA and Carbide are out of sync.
// If so, call send_set_vni_command to send the heart beat or set vni
async fn do_heartbeat<'a>(
    state: &mut DpaInterface,
    services: &mut DbServices,
    client: Arc<MqtteaClient>,
    dpa_info: &Arc<DpaInfo>,
    hb_interval: TimeDelta,
    needs_vni: bool,
) -> CarbideResult<Option<PgTransaction<'a>>> {
    let mut send_hb = false;
    let mut send_revision = false;

    // We are in the Ready or Assigned state and we continue to be in the same state.
    // In this state, we will send SetVni command to the DPA if
    //    (1) if the heartbeat interval has elapsed since the heartbeat
    //    (2) The DPA sent us an ack and it looks like the DPA lost its config (due to powercycle potentially)
    // Heartbeat is identified by the revision being se to the sentinel value "NIL"
    // Both send_hb and send_revision could evaluate to true below. If send_hb is true, we will
    // update the last_hb_time for the interface entry.

    if let Some(next_hb_time) = state.last_hb_time.checked_add_signed(hb_interval)
        && chrono::Utc::now() >= next_hb_time
    {
        send_hb = true; // heartbeat interval elapsed since the last heartbeat 
    }

    if !state.managed_host_network_config_version_synced() {
        send_revision = true; // DPA config not in sync with us. So resend the config
    }

    if send_hb || send_revision {
        let txn = send_set_vni_command(
            state,
            services,
            client,
            dpa_info,
            needs_vni,
            send_hb,
            send_revision,
        )
        .await?;
        Ok(txn)
    } else {
        Ok(None)
    }
}

// Send a SetVni command to the DPA. The SetVni command could be a heart beat (identified by
// revision being "NIL"). If needs_vni is true, get the VNI to use from the DB. Otherwise, vni
// sent is 0.
async fn send_set_vni_command<'a>(
    state: &mut DpaInterface,
    services: &mut DbServices,
    client: Arc<MqtteaClient>,
    dpa_info: &Arc<DpaInfo>,
    needs_vni: bool,
    heart_beat: bool,
    send_revision: bool,
) -> CarbideResult<Option<PgTransaction<'a>>> {
    let revision_str = if send_revision {
        state.network_config.version.to_string()
    } else {
        "NIL".to_string()
    };

    let vni = if needs_vni {
        match get_dpa_vni(state, &mut services.db_reader).await {
            Ok(dv) => dv,
            Err(e) => {
                return Err(eyre::eyre!("get_dpa_vni error: {:#?}", e).into());
            }
        }
    } else {
        0
    };

    // Send a heartbeat command, indicated by the revision string being "NIL".
    match crate::dpa::handler::send_dpa_command(
        client,
        dpa_info,
        state.mac_address.to_string(),
        revision_str,
        vni,
    )
    .await
    {
        Ok(()) => {
            if heart_beat {
                let mut txn = services.db_pool.begin().await.map_err(|e| db::AnnotatedSqlxError::new("dpa_monitor hb begin txn", e))?;
                let res = db::dpa_interface::update_last_hb_time(state, &mut txn).await;
                if res.is_err() {
                    tracing::error!(
                        "Error updating last_hb_time for dpa id: {} res: {:#?}",
                        state.id,
                        res
                    );
                }
                Ok(Some(txn))
            } else {
                Ok(None)
            }
        }
        Err(_e) => Ok(None),
    }
}
