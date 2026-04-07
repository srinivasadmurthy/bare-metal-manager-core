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
use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};

pub(crate) async fn create(
    _api: &Api,
    request: Request<rpc::SpxPartitionCreationRequest>,
) -> Result<Response<rpc::SpxPartition>, Status> {
    log_request_data(&request);

    let _spx_partition_creation_request = request.into_inner();

    Ok(Response::new(rpc::SpxPartition::default()))
}

pub(crate) async fn delete(
    _api: &Api,
    request: Request<rpc::SpxPartitionDeletionRequest>,
) -> Result<Response<rpc::SpxPartitionDeletionResult>, Status> {
    log_request_data(&request);

    let _spx_partition_deletion_request = request.into_inner();

    Ok(Response::new(rpc::SpxPartitionDeletionResult::default()))
}

pub(crate) async fn find_ids(
    _api: &Api,
    request: Request<rpc::SpxPartitionSearchFilter>,
) -> Result<Response<rpc::SpxPartitionIdList>, Status> {
    log_request_data(&request);

    let _spx_partition_search_filter = request.into_inner();

    Ok(Response::new(rpc::SpxPartitionIdList::default()))
}

pub(crate) async fn find_by_ids(
    _api: &Api,
    request: Request<rpc::SpxPartitionsByIdsRequest>,
) -> Result<Response<rpc::SpxPartitionList>, Status> {
    log_request_data(&request);

    let _spx_partitions_by_ids_request = request.into_inner();

    Ok(Response::new(rpc::SpxPartitionList::default()))
}