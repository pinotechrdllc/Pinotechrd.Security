-- Roles as README "Database roles and poolers" describes. sec_owner (the container's POSTGRES_USER) owns the schemas
-- and runs provisioning; the application logs in with one role per tenant; the tenant store reads the catalog only.
CREATE ROLE tenant_acme_app LOGIN PASSWORD 'app-acme-pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE tenant_globex_app LOGIN PASSWORD 'app-globex-pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE catalog_app LOGIN PASSWORD 'catalog-pass' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO tenant_acme_app, tenant_globex_app, catalog_app;
