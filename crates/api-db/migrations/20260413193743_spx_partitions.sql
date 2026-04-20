-- Add migration script here
CREATE TABLE IF NOT EXISTS spx_partitions
(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,

    name VARCHAR(256) NOT NULL DEFAULT (''),
    description VARCHAR(1024) NOT NULL DEFAULT (''),
    tenant_organization_id VARCHAR(64) NOT NULL,
    config_version VARCHAR(64) NOT NULL,
    vni integer NULL UNIQUE;

    created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted TIMESTAMPTZ
);
