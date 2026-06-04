# Agent Instructions

## Git Hooks

The Git hooks for this repository (such as the `prepare-commit-msg` hook) should be taken from:
https://github.com/alg-create/agentic-git-hooks

## AI-Developed Patches

When a patch is fully developed by an AI assistant, create the Git hook sentinel file before the user commits:

```sh
printf '%s\n' '<assistant-id>' > "$(git rev-parse --git-dir)/AI_COAUTHORED"
```

Use the assistant identifier that matches the AI used, for example:

- `codex`
- `antigravity`
- `Name <email@example.com>`

The local `prepare-commit-msg` hook reads this sentinel and adds the matching `Co-authored-by` trailer, then removes the sentinel so it does not affect later human-only commits.

Do not create the sentinel for patches where the AI only reviewed, explained, or lightly assisted with user-authored changes.
