# Security policy

## Supported versions

Only the latest release of vrf-ping gets security fixes. Upgrading is a binary
swap; the `targets/` and `data/` directories stay compatible.

## Reporting a vulnerability

Please report privately, not in a public issue: on GitHub open the
repository's **Security** tab and choose **Report a vulnerability**. Include the
version (`vrf-ping --version`), how it is deployed (behind a proxy or not, with
or without a login), and steps to reproduce.

You should get a first answer within 7 days. Fixed issues are listed in the
release notes of the version that fixes them, with credit if you want it.

## Scope and known design choices

- vrf-ping does not terminate TLS. Put it behind a reverse proxy with TLS, or
  bind it to localhost (`--localhost`), when it is reachable beyond a trusted
  network.
- Without `user=` / `passwd=` the web UI is open to everyone who can reach the
  port, and routing edits are refused. Use a login on anything but a lab.
- Release archives carry SHA-256 checksums (`SHA256SUMS`).
- vrf-ping makes no outbound requests besides the probes you configure, and
  shows no advertising.
- Dependencies and the Go toolchain are checked with `govulncheck`, and the code
  with `staticcheck`, on every push; `govulncheck` also runs weekly.
