-- The application logs in with this role: not superuser, no CREATE anywhere. The owner (POSTGRES_USER) creates the
-- schemas and tables when the sample provisions, then grants this role what it needs (see SampleProvisioning.cs).
-- For one role per tenant, see the library README, "Database roles and poolers".
CREATE ROLE sample_app LOGIN PASSWORD 'sample-app-pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO sample_app;
