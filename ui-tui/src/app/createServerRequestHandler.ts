import type { ServerRequest } from '@hermes/shared/json-rpc-channel'

import type { ClarifyBatchQuestion } from '../types.js'

import { patchOverlayState } from './overlayStore.js'
import { rememberServerRequest, respondToServerRequest } from './serverRequestStore.js'

export interface ServerRequestHandlerContext {
  ringPromptBell: () => void
  setStatus: (status: string) => void
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '')

const strList = (v: unknown): null | string[] =>
  Array.isArray(v) && v.length > 0 ? v.filter((c): c is string => typeof c === 'string') : null

/**
 * The Ink TUI's answer to the backend's server→client requests
 * (`tui_gateway/server_requests.py`). Each method opens its overlay card;
 * the card's answer path resolves the request through `serverRequestStore`.
 * Methods the terminal cannot answer (desktop GUI bridges: `preview.*`,
 * `window.read`, `tour`, `mcp.setup`, `terminal.read`, the vault card
 * prompts) return `false` so the channel answers `-32601` and the tool
 * fails fast instead of waiting out its deadline.
 */
export function createServerRequestHandler(ctx: ServerRequestHandlerContext): (request: ServerRequest) => boolean {
  const { ringPromptBell, setStatus } = ctx

  const open = (request: ServerRequest, status: string) => {
    rememberServerRequest(request)
    setStatus(status)

    if (!request.replayed) {
      ringPromptBell()
    }
  }

  return request => {
    const p = request.params

    switch (request.method) {
      case 'clarify': {
        const batch: ClarifyBatchQuestion[] = (Array.isArray(p.questions) ? (p.questions as unknown[]) : [])
          .map(raw => (raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {}))
          .filter(q => str(q.qid) && str(q.question).trim())
          .map(q => ({
            choices: strList(q.choices),
            multiSelect: q.multi_select === true,
            qid: str(q.qid),
            question: str(q.question).trim()
          }))

        const answers =
          p.answers && typeof p.answers === 'object'
            ? Object.fromEntries(
                Object.entries(p.answers as Record<string, unknown>).filter(
                  (entry): entry is [string, string] => typeof entry[1] === 'string'
                )
              )
            : {}

        patchOverlayState({
          clarify: batch.length
            ? { answers, choices: null, question: '', questions: batch, requestId: request.id }
            : { choices: strList(p.choices), question: str(p.question), requestId: request.id }
        })
        open(request, 'waiting for input…')

        return true
      }

      case 'approval': {
        patchOverlayState({
          approval: {
            // Only an explicit false (tirith warning) drops the permanent-allow option.
            allowPermanent: p.allow_permanent !== false,
            choices: strList(p.choices) ?? undefined,
            command: str(p.command),
            description: str(p.description) || 'dangerous command',
            requestId: request.id,
            smartDenied: p.smart_denied === true
          }
        })
        open(request, 'approval needed')

        return true
      }

      case 'sudo':
        patchOverlayState({ sudo: { requestId: request.id } })
        open(request, 'sudo password needed')

        return true

      case 'secret':
        patchOverlayState({ secret: { envVar: str(p.env_var), prompt: str(p.prompt), requestId: request.id } })
        open(request, 'secret input needed')

        return true

      // Level `plain` only (a keypress, nothing proven), which is all the terminal advertises. Any other
      // level never reaches it; if one does, decline to handle it (-32601) rather than answer a level it
      // cannot satisfy. `verified` is the gateway's to decide, so it is not sent.
      case 'confirm': {
        if (p.level !== 'plain') {
          return false
        }

        const answer = (decision: 'confirmed' | 'declined') =>
          respondToServerRequest(request.id, { decision, method: 'tap' })

        const detail = str(p.detail)

        patchOverlayState({
          confirm: {
            cancelLabel: 'Decline',
            confirmLabel: 'Confirm',
            danger: true,
            detail: detail ? `${str(p.summary)}\n\n${detail}` : str(p.summary),
            onCancel: () => void answer('declined'),
            onConfirm: () => void answer('confirmed'),
            requestId: request.id,
            title: `Agent asks: ${str(p.title)}`,
            wrapDetail: true
          }
        })
        open(request, 'confirmation needed')

        return true
      }

      case 'vault.unlock_prompt':
        patchOverlayState({
          vaultUnlock: { backend: str(p.backend), displayName: str(p.display_name), requestId: request.id }
        })
        open(request, `unlock ${str(p.display_name)}`)

        return true

      default:
        return false
    }
  }
}
