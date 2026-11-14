# Changelog

## 0.7.1

- `editor.applyRemote(from, to, text)` (or a list of `{ from, to, text }`) applies
  someone else's edit without an undo step: undo and redo keep taking back only the
  writer's own edits, the caret and selection stay where they were, focus and scroll
  are left alone, and no `input` event fires. During an IME composition it returns
  `false` and changes nothing. `editor.replace` is unchanged.
