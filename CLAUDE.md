# allauth-fetch Project Context

## Project Overview
This is a TypeScript client library for Django Allauth authentication API. It provides a fetch-based interface to interact with Django Allauth's headless/API mode.

## Key Information
- **Single Module Library**: All code is in `index.ts`
- **Published on JSR**: `@knowsuchagency/allauth-fetch`
- **License**: MIT

## Development Guidelines

### Tools and Commands
- Use `bun` instead of npm for package management
- Prefix Python commands with `uv run` (though this is primarily a TypeScript project)

### Code Style
- Follow existing TypeScript conventions in `index.ts`
- Maintain comprehensive type definitions for all API interfaces
- Ensure both browser and app client modes remain functional

### Testing
- Currently no tests exist in the project
- When implementing tests, check for testing framework preference first

### Git Workflow
- Currently on branch: `empty-base-url`
- Main branch is used for PRs
- Do NOT mention AI/Claude in commit messages

### Important Notes
- This library supports two client types:
  - Browser Client (cookie-based sessions)
  - App Client (token-based with customizable storage)
- CSRF token handling is automatic for non-GET requests
- All authentication endpoints follow Django Allauth's OpenAPI spec

### Project Structure
```
/Users/stephanfitzpatrick/projects/allauth-fetch/
├── index.ts         # Main source file (entire library)
├── jsr.json         # JSR package configuration
├── package.json     # NPM package configuration
├── README.md        # Comprehensive documentation
└── LICENSE          # MIT License
```

### When Making Changes
1. All code changes go in `index.ts`
2. Update version in `jsr.json` when making releases
3. Ensure TypeScript types remain comprehensive
