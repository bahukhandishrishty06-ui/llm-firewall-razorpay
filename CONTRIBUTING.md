# Contributing to PayGuard

Thank you for your interest in contributing to **PayGuard**! This project is designed as a defensive security framework for agentic commerce and AI payment agents.

## 🛡️ Responsible Disclosure & Defensive Scope

1. **Defensive Research Only**: All contributions must focus strictly on detection, defense, screening, anomaly tracking, and policy enforcement.
2. **Synthetic Data**: Never commit real customer PII, real payment secrets, or live gateway credentials.
3. **No Attack Generation Tools**: Contributions must not include offensive exploit automation or weaponized jailbreak synthesizers.

## 🛠️ Local Development Workflow

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   make install
   ```
3. Generate the test dataset:
   ```bash
   make dataset
   ```
4. Run the test suite:
   ```bash
   make test
   ```
5. Run the offline evaluation pipeline:
   ```bash
   make eval
   ```

## 🧪 Code Quality Standards

- Ensure all new features include unit tests in `tests/`.
- Maintain sub-millisecond screening latency for Layer 1 heuristic detectors.
- Run `pytest` before opening a pull request.
