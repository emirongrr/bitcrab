# Contributing

Bitcrab accepts Bitcoin implementation work and reproducible post-quantum
Bitcoin research.

## Correctness Rules

- Bitcoin Core C++ is the behavioral reference for Bitcoin consensus and P2P.
- Research rules must remain isolated from normal Bitcoin validation.
- Do not describe modeled or synthetic results as measured cryptographic
  results.
- Do not claim historical ownership from deterministic synthetic keys.
- New real cryptographic backends require official known-answer tests and
  differential tests against an independent implementation.

## Change Requirements

- Keep changes scoped to existing crate ownership boundaries.
- Add Bitcoin Core vectors or references for changed Bitcoin behavior.
- Add explicit assumptions and evidence labels for research models.
- Keep dependencies minimal and explain new cryptographic dependencies.
- Include focused tests and run `cargo clippy -- -D warnings` for touched
  crates.

## Benchmark Reports

A publishable benchmark should include:

- source chain and tip;
- code revision and authorization manifest ID;
- algorithm, parameter set, and backend revision;
- modeled, measured, and synthetic field labels;
- hardware, operating system, compiler, thread count, and cache settings;
- raw output sufficient for independent reproduction.

Security conclusions require cryptographic review beyond benchmark success.
