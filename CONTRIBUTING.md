# Contributing to ctf-writeups

Thanks for your interest in contributing! This is a security research project — contributions that improve accuracy, add new attack techniques, or improve defenses are very welcome.

## Ways to Contribute

- **New attack modules** — implement a new PoC or attack technique
- **New payloads** — add payloads to existing modules
- **Bug fixes** — fix broken detection logic or false positives
- **Documentation** — improve write-ups, add examples, fix typos
- **CTF write-ups** — add your own write-ups following the template

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-attack`
3. Make your changes
4. Test everything works: `python run_all.py` (or `python demo.py`)
5. Commit with a clear message: `git commit -m "Add LLM01: new Unicode smuggling payload"`
6. Push and open a Pull Request

## Code Standards

- Python 3.9+ compatible
- No external dependencies unless absolutely necessary (keep stdlib-only where possible)
- Every new attack module must have a `run(adapter=None)` method that works in simulation mode
- Include MITRE ATLAS or OWASP reference in your module docstring
- Follow the existing `Finding` dataclass structure for all findings

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include a description of what the change does and why
- If adding a new attack, explain the real-world scenario it maps to
- All existing modules must still pass after your change

## Legal

By contributing, you agree that your contributions will be licensed under the MIT License. All contributions must be for **educational and authorised security research purposes only**.

## Questions?

Open a GitHub Discussion or reach out via the contact info in [SECURITY.md](SECURITY.md).
