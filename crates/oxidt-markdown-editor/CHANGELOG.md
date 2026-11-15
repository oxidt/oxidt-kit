# Changelog

## 0.7.2

- `/link` in the slash menu ("Link to page", label key `link`) writes `[[` and opens the
  host's completions, for keyboards where `[` is hard to reach. It is offered only when
  `data-completion-triggers` includes `[[`, and unlike the block commands it also works
  after a space within a line.

## 0.7.1

- `editor.applyRemote(from, to, text)` (or a list of `{ from, to, text }`) applies
  someone else's edit without an undo step: undo and redo keep taking back only the
  writer's own edits, the caret and selection stay where they were, focus and scroll
  are left alone, and no `input` event fires. During an IME composition it returns
  `false` and changes nothing. `editor.replace` is unchanged.
