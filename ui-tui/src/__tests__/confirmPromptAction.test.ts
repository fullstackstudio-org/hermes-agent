import { describe, expect, it } from 'vitest'

import { CONFIRM_INPUT_GRACE_MS, confirmPromptAction } from '../components/prompts.js'

const after = CONFIRM_INPUT_GRACE_MS + 1

describe('confirmPromptAction', () => {
  it('keeps Y/N shortcuts for a local confirm', () => {
    expect(confirmPromptAction('y', {}, 0, { deliberate: false, elapsedMs: 0 })).toBe('confirm')
    expect(confirmPromptAction('n', {}, 1, { deliberate: false, elapsedMs: 0 })).toBe('cancel')
  })

  it('ignores every key on a backend confirm until the grace period has passed', () => {
    for (const [ch, key] of [
      ['y', {}],
      ['', { return: true }],
      ['', { escape: true }],
      ['', { downArrow: true }]
    ] as const) {
      expect(confirmPromptAction(ch, key, 1, { deliberate: true, elapsedMs: CONFIRM_INPUT_GRACE_MS - 1 })).toBe('noop')
    }
  })

  it('confirms a backend request only with Enter on an explicitly selected Confirm', () => {
    expect(confirmPromptAction('y', {}, 1, { deliberate: true, elapsedMs: after })).toBe('noop')
    expect(confirmPromptAction('', { return: true }, 0, { deliberate: true, elapsedMs: after })).toBe('cancel')
    expect(confirmPromptAction('', { downArrow: true }, 0, { deliberate: true, elapsedMs: after })).toBe('down')
    expect(confirmPromptAction('', { return: true }, 1, { deliberate: true, elapsedMs: after })).toBe('confirm')
    expect(confirmPromptAction('', { escape: true }, 1, { deliberate: true, elapsedMs: after })).toBe('cancel')
  })
})
