-- Per-scan response status.
--
-- The endpoints table stores the *latest* observed status for an endpoint, so a
-- comparison between two scans cannot read it: the row is shared. Recording the
-- status on the join table keeps each scan's observation intact.
ALTER TABLE scan_endpoints ADD COLUMN response_status INTEGER;
