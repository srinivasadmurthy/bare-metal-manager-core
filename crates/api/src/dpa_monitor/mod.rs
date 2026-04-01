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

use crate::periodic_timer::PeriodicTimer;
use db::work_lock_manager::WorkLockManagerHandle;
use db::{self};
use sqlx::{PgConnection, PgPool};
use std::time::Duration;

use crate::CarbideResult;
use crate::api::TransactionVending;
use crate::cfg::file::DpaConfig;
use mqttea::client::MqtteaClient;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use model::machine::{HostHealthConfig, LoadSnapshotOptions, ManagedHostStateSnapshot};
use model::machine::machine_search_config::MachineSearchConfig;
use model::dpa_interface::{DpaInterfaceControllerState};

use metrics::{DpaMonitorMetrics};

use tracing::Instrument;

mod metrics;

#[allow(dead_code)]
pub struct DpaMonitor {
    db_pool: PgPool,
    mqtt_client: Option<Arc<MqtteaClient>>,
    config: DpaConfig,
    host_health: HostHealthConfig,
    metric_holder: Arc<metrics::MetricHolder>,
    work_lock_manager_handle: WorkLockManagerHandle,
    last_dpa_info_validation: std::sync::Mutex<Option<std::time::Instant>>,
}

impl DpaMonitor {
    const ITERATION_WORK_KEY: &'static str = "DpaMonitor::run_single_iteration";

    pub fn new(
        db_pool: PgPool,
        mqtt_client: Option<Arc<MqtteaClient>>,
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
            db_pool: db_pool,
            mqtt_client: mqtt_client,
            config: config,
            host_health: host_health,
            work_lock_manager_handle: work_lock_manager_handle,
            last_dpa_info_validation: std::sync::Mutex::new(None),
            metric_holder: metric_holder,
        }
    }

    pub fn start(
        self,
        join_set: &mut JoinSet<()>,
        cancel_token: CancellationToken,
    ) -> io::Result<()> {
        if self.config.enabled {
            join_set
                .build_task()
                .name("dpa-monitor")
                .spawn(async move { self.run(cancel_token).await })?;
        }

        Ok(())
    }

    pub async fn run(&self, cancel_token: CancellationToken) {
        let timer = PeriodicTimer::new(self.config.monitor_run_interval);
        loop {
            let mut tick = timer.tick();
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

    pub async fn run_single_iteration(&self) -> CarbideResult<usize> {
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

    async fn run_single_iteration_inner(&self, metrics: &mut DpaMonitorMetrics) -> CarbideResult<usize> {
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
        tracing::trace!(
            lock = Self::ITERATION_WORK_KEY,
            "DpaMonitor acquired the lock",
        );

        let mut txn = self.db_pool.txn_begin().await?;

        let mut snapshots = match self.get_all_snapshots(&mut txn).await {
            Ok(snapshots) => snapshots,
            Err(e) => {
                tracing::error!(error = %e, "Failed to load ManagedHost snapshots in IbFabricMonitor");
                // Record the same error for all fabrics, so that the problem is at least visible on dashboards
                return Err(e);
            }
        };

        txn.commit().await?;

        for mh in snapshots.values_mut() {
            metrics.num_machines_scanned += 1;

            // If the machine does not have any dpa interfaces, we can skip it.
            if mh.dpa_interface_snapshots.is_empty() {
                continue;
            }

            // If the machine is an instance, increment the number of instances scanned.
            if mh.instance.is_some() {
                metrics.num_instances_scanned += 1;
            }

            for idx in 0..mh.dpa_interface_snapshots.len() {
                metrics.num_dpa_interfaces_scanned += 1;

                // Look at this DPA interface and see if we need to transition it to a new state.
                // This will return a new state if we need to transition to a new state, or None if we can stay in the current state.
                // We build an array of dpa interfaces and new state.
                // After examining all the dpa interfaces in all the machines, we will update the DB with the new states in another loop
                self.handle_dpa_interface(mh, idx).await?;
            }
        }

        Ok(0)
    }

    async fn handle_dpa_interface(
        &self,
        mh: &mut ManagedHostStateSnapshot,
        idx: usize,
    ) -> CarbideResult<()> {
        let dpa_interface = &mut mh.dpa_interface_snapshots[idx];

        let controller_state = dpa_interface.controller_state.value.clone();
        match controller_state {
            DpaInterfaceControllerState::Provisioning => {
                if dpa_interface.use_admin_network() {
                    return Ok(());
                }

                let new_state = DpaInterfaceControllerState::Ready;
                tracing::info!(state = ?new_state, "Dpa Interface state transition");
                return Ok(());
            }
            _ => {}
        }
        Ok(())
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
        db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: true,
                host_health_config: self.host_health,
            },
        )
        .await
        .map_err(Into::into)
    }
}
