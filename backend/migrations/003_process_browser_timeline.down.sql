-- Reversible down-migration for Migration 002
DROP TABLE IF EXISTS correlation_reviews;
DROP TABLE IF EXISTS correlation_links;
DROP TABLE IF EXISTS browser_download_revisions;
DROP TABLE IF EXISTS browser_downloads;
DROP TABLE IF EXISTS browser_navigations;
DROP TABLE IF EXISTS browser_collection_gaps;
DROP TABLE IF EXISTS browser_profiles;
DROP TABLE IF EXISTS process_lifecycle_events;
DROP TABLE IF EXISTS process_samples;
DROP TABLE IF EXISTS process_instances;
DROP TABLE IF EXISTS process_snapshots;
