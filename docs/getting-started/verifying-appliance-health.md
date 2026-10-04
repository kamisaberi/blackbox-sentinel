# Verifying Appliance Health

> **Status:** Draft — placeholder content. Final technical prose is forthcoming.


Health inspection via CLI, systemd, and the local web UI.

## CLI

sentinel --health prints subsystem states, ring depth, and map sizes in one screen.

## Daemon & UI

systemctl status plus the :8443 dashboard agree — any mismatch is itself an alert.

---

*Part of the blackbox-sentinel documentation set. See mkdocs.yml for navigation.*
