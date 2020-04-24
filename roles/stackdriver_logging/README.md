# stackdriver_logging

Ansible role to install the Stackdriver Logging Agent.

## Requirements

Permissions to Google Cloud API. If running on an old Compute Engine instance or
Compute Engine instances created without the default credentials, then you must
complete the following steps
<https://cloud.google.com/logging/docs/agent/authorization#before_you_begin>

## Role Variables

| Variable                       | Default                        | Comments                                           |
| ------------------------------ | ------------------------------ | -------------------------------------------------- |
| `stackdriver_log_service_name` | Please see `defaults/main.yml` | Stackdriver service name                           |
| `stackdriver_log_package_name` | Please see `defaults/main.yml` | Package name of the Stackdriver agent              |
| `stackdriver_log_repo_host`    | Please see `defaults/main.yml` | Hostname of the repository the package is loacated |
| `stackdriver_log_repo_suffix`  | Please see `defaults/main.yml` | Sufffix for the repository ex. `all`               |
| `stackdriver_http_proxy`       | Undefined                      | HTTP Proxy for Stackdriver                         |
| `stackdriver_https_proxy`      | Undefined                      | HTTPS Proxy for Stackdriver                        |
| `stackdriver_no_proxy`         | Undefined                      | Skip proxy for the local Metadata Server.          |

### Debian Specific

| Variable                        | Required                       | Comments                                             |
| ------------------------------- | ------------------------------ | ---------------------------------------------------- |
| `stackdriver_log_apt_repo_url`  | Please see `defaults/main.yml` | APT repository url                                   |
| `stackdriver_log_apt_gpg_key`   | Please see `defaults/main.yml` | GPG Key for verifying the APT repository.            |
| `stackdriver_log_apt_repo_name` | Please see `defaults/main.yml` | Skips any requirements for disk space, ram, and cpu. |

### RedHat Specific

| Variable                        | Required                       | Comments                                             |
| ------------------------------- | ------------------------------ | ---------------------------------------------------- |
| `stackdriver_log_yum_repo_url`  | Please see `defaults/main.yml` | Skips any requirements for disk space, ram, and cpu. |
| `stackdriver_log_yum_repo_name` | Please see `defaults/main.yml` | Skips any requirements for disk space, ram, and cpu. |
| `stackdriver_log_yum_repo`      | Please see `defaults/main.yml` | Skips any requirements for disk space, ram, and cpu. |
| `stackdriver_log_yum_gpg_key`   | Please see `defaults/main.yml` | Skips any requirements for disk space, ram, and cpu. |
| `stackdriver_log_service_name`  | Please see `defaults/main.yml` | Skips any requirements for disk space, ram, and cpu. |

## Dependencies

## Example Playbook

```yaml
- hosts: localhost
  become: yes
  roles:
    - role: google.cloud.stackdriver_logging
```

## License

GPLv3

## Author Information

[Eric Anderson](https://ericsysmin.com)
