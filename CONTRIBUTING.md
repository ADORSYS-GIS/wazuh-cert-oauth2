# Contributing to Wazuh Certificate OAuth2

Thank you for your interest in contributing to this project! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Rust 1.85+ (2024 edition)
- OpenSSL development libraries
- Docker and Docker Compose (for testing)

### Setting Up the Development Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/ADORSYS-GIS/wazuh-cert-oauth2.git
   cd wazuh-cert-oauth2
   ```

2. Install pre-commit hooks:
   ```bash
   pip install pre-commit
   pre-commit install
   ```

3. Build the project:
   ```bash
   cargo build
   ```

4. Run tests:
   ```bash
   cargo test
   ```

## Development Workflow

### Branching Strategy

- `main` - stable branch, protected
- Feature branches should be created from `main`
- Use descriptive branch names: `feature/add-xyz`, `fix/issue-123`, `docs/update-readme`

### Code Style

This project uses standard Rust formatting and linting:

- **Formatting**: Run `cargo fmt` before committing
- **Linting**: Run `cargo clippy` and address warnings
- **Pre-commit**: Hooks will automatically check formatting and run clippy

### Commit Messages

Use clear, descriptive commit messages:

- Use the imperative mood ("Add feature" not "Added feature")
- Keep the first line under 72 characters
- Reference issues when applicable: `Fix #123: Resolve token refresh issue`

## Making Changes

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with appropriate tests
3. Ensure all checks pass:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
4. Push your branch and open a Pull Request
5. Fill out the PR template completely
6. Wait for review and address feedback

### What We Look For

- Code follows existing patterns and style
- Changes include appropriate tests
- Documentation is updated if needed
- Commits are atomic and well-described
- No unnecessary dependencies added

## Reporting Issues

### Bug Reports

When reporting bugs, please include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Environment details (OS, Rust version, etc.)
- Relevant logs or error messages

### Feature Requests

For feature requests, please describe:

- The problem you're trying to solve
- Your proposed solution
- Alternative approaches you've considered

## Project Structure

```
wazuh-cert-oauth2/
├── crates/
│   ├── wazuh-cert-oauth2-server/    # OAuth2 server with certificate issuance
│   ├── wazuh-cert-oauth2-client/    # CLI client for agent registration
│   ├── wazuh-cert-oauth2-webhook/   # IdP webhook handler
│   ├── wazuh-cert-oauth2-model/     # Shared types and utilities
│   └── wazuh-cert-oauth2-healthcheck/ # Health check utility
├── charts/                          # Helm charts for Kubernetes
└── compose.yaml                     # Docker Compose for local development
```

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Be respectful and constructive in discussions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
