# Contributing to Quantum Encryptor

Thank you for your interest in contributing to the Quantum Encryptor project! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct.

## How Can I Contribute?

### Reporting Bugs

- Check if the bug has already been reported in [GitHub Issues](https://github.com/brainx/Quantum-Encryptor/issues)
- Use the bug report template when creating a new issue
- Provide detailed steps to reproduce the bug
- Include information about your environment (OS, Python version, etc.)
- If possible, add a minimal code example that demonstrates the issue

### Suggesting Enhancements

- Check if the enhancement has already been suggested in [GitHub Issues](https://github.com/brainx/Quantum-Encryptor/issues)
- Use the feature request template when creating a new issue
- Clearly describe the enhancement and its expected benefits
- Consider how the enhancement aligns with the project's goals

### Pull Requests

- Fork the repository and create a new branch for your contribution
- Follow the existing code style and conventions
- Add tests for new functionality
- Ensure all tests pass
- Update documentation as needed
- Create a clear pull request description

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/brainx/Quantum-Encryptor.git
   cd Quantum-Encryptor
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -e .  # Install in development mode
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

## Coding Standards

### Style Guide

- Follow PEP 8 for code style
- Use snake_case for variables and functions
- Use CapWords for classes
- Use UPPER_CASE for constants
- Use Black for automatic code formatting

### Documentation

- Document all public functions, classes, and modules with Google-style docstrings
- Keep docstrings up-to-date with code changes
- Include type hints for function parameters and return types

### Testing

- Write unit tests for new functionality
- Try to maintain or improve test coverage
- Run the test suite before submitting a pull request:
  ```bash
  PYTHON=.venv/bin/python ./test.sh
  ```

### Type Checking

- Use type hints for all new code
- Run mypy to check static typing:
  ```bash
  .venv/bin/python -m mypy \
    crypto_config.py crypto_core.py pqc_agent_tools.py pqc_app.py \
    tests/test_agent_tools.py tests/test_crypto_core.py
  ```

## Commit Messages

- Use the conventional commits format (https://www.conventionalcommits.org/)
- Keep the first line under 72 characters
- Use the imperative mood ("Add feature" not "Added feature")
- Reference issues and pull requests when relevant

## Code Review Process

- All submissions will be reviewed by project maintainers
- Maintainers may request changes before accepting contributions
- Be responsive to feedback and questions during the review process

## Additional Resources

- [Project Repository](https://github.com/brainx/Quantum-Encryptor)
- [Issue Tracker](https://github.com/brainx/Quantum-Encryptor/issues)
- [Open Quantum Safe Documentation](https://openquantumsafe.org/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/Projects/post-quantum-cryptography)

Thank you for contributing to the Quantum Encryptor project!
