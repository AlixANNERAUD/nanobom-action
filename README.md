# nanobom SBOM upload

[![Test](https://github.com/AlixANNERAUD/nanobom-action/actions/workflows/test.yml/badge.svg)](https://github.com/AlixANNERAUD/nanobom-action/actions/workflows/test.yml)

A GitHub Action that uploads a CycloneDX SBOM to [nanobom](https://github.com/AlixANNERAUD/nanobom)
and reports the project's vulnerabilities in the job: a summary table, annotations, outputs, and
optionally a failing job when findings cross a threshold.

```yaml
- uses: AlixANNERAUD/nanobom-action@v1
  with:
    url: ${{ vars.NANOBOM_URL }}
    token: ${{ secrets.NANOBOM_TOKEN }}
    organization: acme
    fail-on: high
```

Without an `sbom`, the action generates one with [Syft](https://github.com/anchore/syft) (through
[anchore/sbom-action](https://github.com/anchore/sbom-action)) from the checkout. The project
defaults to the repository's name and is created by its first upload.

## Setup

1. In nanobom, open the organization's settings and create an **upload token** (it is shown
   once). A token of the organization can create projects; a token of one project uploads to it
   only.
2. In the repository's settings, add the token as the secret `NANOBOM_TOKEN` and the instance's
   address as the variable `NANOBOM_URL`.
3. Add the step after the checkout (and after the build, if the SBOM comes from build output).

## Inputs

| Input | Default | |
| --- | --- | --- |
| `url` | required | Address of the nanobom instance |
| `token` | required | Upload token |
| `organization` | required | Organization slug |
| `project` | repository name | Project slug |
| `sbom` | | Path of an existing CycloneDX JSON SBOM; without it, one is generated |
| `scan-path` | `.` | Directory Syft scans when no `sbom` is given |
| `scan-image` | | Container image Syft scans instead of `scan-path` |
| `fail-on` | | Fail when open findings are at or above `critical`, `high`, `medium` or `low`, or when one is known `exploited` (CISA KEV); implies `wait` |
| `wait` | `true` | Wait for the evaluation and report it |
| `source-commit` | the workflow's commit | Commit shown in the project's upload history |
| `image-tag` | the Git tag, if any | Image tag shown in the upload history |
| `summary` | `true` | Write the evaluation to the job summary |

## Outputs

| Output | |
| --- | --- |
| `http-status` | HTTP status of the upload |
| `project-url` | The project's page in nanobom |
| `evaluation-status` | `succeeded`, `failed` or `timed_out`; empty without `wait` |
| `critical`, `high`, `medium`, `low` | Open findings of the project by severity |
| `known-exploited` | Open findings known to be exploited |
| `sbom` | Path of the uploaded SBOM |

The job fails when the upload is refused (token, project, size, invalid document), when
`fail-on` is crossed (one annotation per finding, up to ten), or when `fail-on` is set and the
evaluation did not complete (OSV unreachable, or longer than the server's
`NANOBOM_UPLOAD_WAIT_SECONDS`). `wait`, `fail-on` and the evaluation need nanobom with the
upload gate; older versions accept the upload and report no evaluation.

## Examples

A container image, released by tag:

```yaml
on:
  push:
    tags: ["v*"]

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
          project: web
          scan-image: ghcr.io/acme/web:${{ github.ref_name }}
          fail-on: exploited
```

An SBOM from the build, with a later step using the outputs:

```yaml
- run: cargo cyclonedx --format json --override-filename sbom
- id: nanobom
  uses: AlixANNERAUD/nanobom-action@v1
  with:
    url: ${{ vars.NANOBOM_URL }}
    token: ${{ secrets.NANOBOM_TOKEN }}
    organization: acme
    sbom: sbom.json
- if: steps.nanobom.outputs.known-exploited != '0'
  run: echo "Known exploited vulnerabilities: ${{ steps.nanobom.outputs.project-url }}"
```

Reverse proxies in front of nanobom must allow the wait: raise their read timeout (nginx's
`proxy_read_timeout` is 60 s by default) above `NANOBOM_UPLOAD_WAIT_SECONDS`, or set
`wait: false` when no `fail-on` is needed.

## Development

`tests/run.sh` runs the upload script against a mock of nanobom's API (needs bash, curl, jq and
python3). CI also runs the action itself against the mock, and against nanobom built from its
main branch.

Releases are tagged `vX.Y.Z`, and the major tag `vX` is moved to the latest of its series.

## License

[Apache-2.0](LICENSE).
