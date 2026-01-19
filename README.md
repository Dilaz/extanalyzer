# Extension Analyzer

A command-line tool for analyzing Chrome and Firefox browser extensions for security issues.

## Features

- Static analysis of JavaScript using AST parsing (oxc)
- Manifest permission analysis with severity classification
- LLM-powered code review (OpenAI, Anthropic, Google Gemini)
- Sandboxed JavaScript execution for deobfuscation
- Supports Chrome Web Store and Firefox Add-ons

## Installation

```bash
cargo build --release
```

## Usage

```bash
# Chrome extension by ID
extanalyzer nkbihfbeogaeaoehlefnkodbefgpgknn

# Firefox extension by slug
extanalyzer --firefox ublock-origin

# By URL
extanalyzer "https://chromewebstore.google.com/detail/xxx"

# Local file
extanalyzer ./extension.crx

# With specific LLM provider
extanalyzer --llm anthropic <id>

# Static analysis only (no LLM)
extanalyzer --no-llm <id>
```

## Environment Variables

Set API keys for LLM providers:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GEMINI_API_KEY`

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.
