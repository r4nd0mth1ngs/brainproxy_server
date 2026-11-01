# brainproxy server

A small self-hosted scan service for [brainproxy](https://github.com/r4nd0mth1ngs/brainproxy).
Pipelines call it after deploying to a dev instance: it scans a registered target, compares the
results with the previous scan, and reports what is new, fixed and unchanged. One server handles
at most 10 targets.

Status: early development. Nothing to install yet.

## How it relates to brainproxy

The server runs the `brainproxy` command line tool as a separate program and reads its JSON output.
It contains no brainproxy code. brainproxy itself is a separate project under the Apache License 2.0.

## License

This project is source-available under the [PolyForm Shield License 1.0.0](LICENSE.md). You may use,
change and run it, including inside a company, for free. Offering it, or something built from it,
as a product or hosted service that competes with it needs permission: open an issue or contact
the author.
