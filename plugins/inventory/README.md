# gcp_compute inventory plugin

Dynamic inventory plugin for Google Cloud Compute Engine. Reads a YAML configuration file
(`*.gcp.yml`/`*.gcp.yaml`/`*.gcp_compute.yml`/`*.gcp_compute.yaml`) and resolves matching
Compute Engine instances into the Ansible inventory. Full option reference is in the
`DOCUMENTATION` block of `gcp_compute.py`.

## `projects:` vs `folders:`

- **`projects:`** — an explicit list of project IDs. The plugin queries Compute Engine
  directly for each one.
- **`folders:`** — one or more GCP folder IDs. The plugin resolves every project under each
  folder, recursively through any nested subfolders, then queries each resolved project the
  same way as with `projects:`. Useful when the set of projects changes over time and
  shouldn't require editing the inventory file.

Both options can be combined; the plugin queries the union of explicit projects and
folder-resolved ones.

## Required IAM permissions

| Config | Permissions | Where to grant them |
|---|---|---|
| `projects:` only | `roles/compute.viewer` (or equivalent) | On each project listed |
| `folders:` | `roles/compute.viewer` on the resolved projects, plus `roles/browser` (grants `resourcemanager.folders.list` and `resourcemanager.projects.list`) | `roles/browser` on the folder(s) passed to `folders:` — inherited automatically by nested subfolders |

`roles/browser` is only needed for the folder-to-project resolution step; it isn't used to
read Compute Engine data itself.

## Behavior when a resolved project can't be queried

When using `folders:`, a project that Resource Manager returns as part of the hierarchy is
not guaranteed to be queryable — for example if Compute Engine isn't enabled on it, or if
it's inside a VPC Service Controls perimeter that blocks the request. In both cases, the
plugin skips that project (emitting a warning) instead of failing the entire inventory sync.
Any other error is still fatal, so a genuine permissions issue isn't silently hidden. If at
least one project was skipped, a single aggregate warning is printed at the end of the sync
(`N out of M project(s) were skipped...`) summarizing how many, in addition to the
per-project warnings already emitted.
