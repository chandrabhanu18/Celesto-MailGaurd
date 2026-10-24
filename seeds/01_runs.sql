-- Run Ledger Seed Script for PostgreSQL
-- Mounted to /docker-entrypoint-initdb.d in Docker Compose
-- Automatically executed on initial container initialization
-- Re-running the SQL does not duplicate the seed record

CREATE TABLE IF NOT EXISTS runs (
    run_id VARCHAR(64) PRIMARY KEY,
    sandbox_name VARCHAR(128) NOT NULL,
    problem_id VARCHAR(64) NOT NULL,
    state VARCHAR(32) NOT NULL,
    execution_target VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target)
VALUES (
    'run-seeddemo1',
    'sbx-seeddemo1',
    'problem-email-quarantine',
    'deleted',
    'celesto_sandbox'
)
ON CONFLICT (run_id) DO NOTHING;
