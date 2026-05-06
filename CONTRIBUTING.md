# Contributing

Contributions are very welcome.

This project aims to remain:
- small and focused
- well-documented
- correct over clever
- safe where possible, explicit where unsafe is required

## How to contribute

You can contribute by:
- reporting bugs
- improving documentation
- adding tests
- reviewing code
- suggesting design improvements

Please open an issue before starting large changes.

## Code style

- Follow idiomatic Rust
- Prefer clarity over cleverness
- Avoid unnecessary abstractions
- Document invariants and safety assumptions

## Commit Guidelines

Commits should be small, focused, and understandable in isolation.
Each commit is expected to represent a working state of the codebase,
even if the feature is not yet complete.

We loosely follow the spirit of *Conventional Commits*, but without rigid
enforcement. Use clear, descriptive commit messages that state **what**
changed in the commit header and **why** in the body.

Recommended prefixes (not mandatory):

- `feat:` new functionality or behavior
- `fix:` bug fixes or correctness issues
- `refactor:` internal restructuring without changing behavior
- `test:` adding or improving tests
- `docs:` documentation changes

Examples:
- `feat: add prefix lifetime handling`
- `fix: handle zero-lifetime RDNSS as explicit withdrawal`
- `test: add integration test for multi-router prefix expiry`

Before opening a pull request, contributors are encouraged to use
`git rebase -i` to clean up intermediate or exploratory commits.
The final history should read as a logical sequence of meaningful steps,
not a work log.

If a change naturally spans multiple commits, ensure that each commit:
- builds successfully
- keeps invariants intact
- does not rely on later commits to be correct

## Testing

All changes should include appropriate tests.

Parser code, in particular, is expected to have thorough edge case coverage.

## Safety

Unsafe code is allowed only where unavoidable (raw sockets, packet parsing).
All unsafe blocks must:
- be minimal
- be documented
- explain why they are correct

## Tracing & Logging

The crate uses `tracing` for observability.

- Do not install global subscribers in the library
- Prefer spans at semantic boundaries
- Avoid excessive log volume in hot paths

## License

By contributing, you agree that your contributions will be licensed under
the same terms as this project: **MIT OR Apache-2.0**.
