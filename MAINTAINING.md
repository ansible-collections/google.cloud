# Maintainer Documentation

## CI GCP Project Configuration

To enable running integration tests, a test GCP project must be provided.

There is a Google-maintained CI project, `ansible-gcp-ci`, that is used for this purpose. For any questions or modification to this project, please contact a maintainer who is employed by Google.

## Reviewing PRs

### Merging PRs

Since running the full set of integration tests requires the usage of GCP
credentials which are stored as a secret, maintainers must verify that tests pass the integration test run that runs on push to the master branch after accepting a change.

