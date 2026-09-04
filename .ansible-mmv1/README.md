# Ansible MMv1 compiler configuration

Contents of this directory:

    .
    ├── config.yaml - Main configuration file, it is auto-discovered if you run ansible-mmv1 from the collection's root folder
    ├── magic-modules - Git-ignored clone of the configured git.repo present in config.yaml
    ├── overlay - Directory with product overlays matching the magic-modules specification
    ├── README.md - This file
    └── templates - Directory with ansible specific templates for this collection

> [!NOTE]  
> A note on templates defined in this directory: the templates stored in this dir are Go based, and *some* templates (mostly integration test templates) also have ansible/jinja2 templates embedded. These share the same syntax, exercise caution on properly escaping jinja2 syntax in go-tpl syntax

# Special directories


## Magic modules directory

Just a git clone of the repo configured in `config.yaml`. This could theoretically be a sub-module and skip the cloning step in the config file, but for now it is just a regular directory with an entry in `.gitignore`


## Overlay directory

    overlay/
    ├── info
    ├── products
    └── templates

The `overlay/info/` is a special customization directory for "info" modules, since TF has no such thing as "info" modules (all modules inherently save the state of the resources defined) we cheat a little bit here and make a special case in case customizations are needed for info modules.

The `overlay/products/` is a directory merged on top of the upstream (magic-modules) directory. However, since upstream is 100% focused on TF, we **need** this directory to specify the proper Ansible customizations.

The `overlay/templates/` at this point stores only the samples for our ansible documentation and integration tests. Samples are prefixed with `ansible_` because that basically guarantees no clashing with the upstream samples. Sample steps have a special nomenclature:

* `ansible_doc_*` - These are for documentation strings i.e. whatever appears in the `DOCUMENTATION` entry for each plugin module
* `ansible_setup_*` - These are for integration tests, these are specifically put at the top of the use case playbook part of the `block` body
* `ansible_test_*` - These are for integration tests, these steps sit in the middle of the playbook right after all setup steps have rendered, also part of the `block` body
* `ansible_teardown_*` - These are for integration tests, these steps are at the end of the playbook, and they are placed in a `finally` section corresponding to the `block` item of each playbook

## Templates directory

Here lie the templates for the output files themselves. These drive whatever is put in the `plugins/modules/` and `test/integration/` directories. You can customize these as needed.
