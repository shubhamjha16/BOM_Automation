"""The completion provider. **The only place in this product a model is called.**

Everything §11 says still holds with this wired in, because none of it depended
on the model being absent:

- The model receives every verdict, figure and clause reference as an *input* and
  may only restate them. `narrative/drafter.verify` checks the output against the
  facts supplied and refuses a draft asserting anything else — a check that runs
  because the model exists, not despite it.
- Retrieved house wording arrives fact-masked, so another engagement's figures
  are not in the prompt to be copied.
- An unavailable provider is a configuration state, not a failure:
  `NullGenerator` restates the findings and marks the section undrafted.

Availability is deliberately three-part — the feature flag, the SDK, and the key —
and each is reported separately, because "no narrative in production" has three
different causes and one of them is a deployment bug.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.configs.envConfig import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class GenerationUnavailable(RuntimeError):
    """The provider is configured but could not be reached."""


def _client() -> Any:
    """Construct the SDK client, or explain precisely what is missing.

    Imported here rather than at module scope so the absence of an optional
    dependency is a runtime state this module reports, not an ImportError that
    takes the whole application down at boot.
    """
    try:
        import anthropic
    except ImportError as error:  # pragma: no cover - optional extra
        raise GenerationUnavailable(
            "the `anthropic` SDK is not installed; narrative drafting is an "
            "optional extra (`uv sync --extra llm`)"
        ) from error

    key = settings.ANTHROPIC_API_KEY
    # **Recognised by the real prefix, not by a list of placeholder spellings.**
    # The key is a *required* config var, so it is never absent — tests, CI and
    # `make demo` all set something. A blocklist of the placeholders we happen to
    # know about (`test-key`, `ci-placeholder`, `x`) misses the next one somebody
    # invents, and the failure mode is a live provider call from a test suite.
    if not key.startswith("sk-ant-"):
        raise GenerationUnavailable(
            "ANTHROPIC_API_KEY does not look like a real key (no `sk-ant-` "
            "prefix). It is a required config var, so a placeholder value means "
            "this deployment never had a real one rather than that it is missing."
        )
    # `max_retries` covers 429 and 5xx with backoff. Two is the SDK default and
    # is right here: a section draft is not on a user's critical path, and a
    # longer retry chain on a provider outage just delays the fallback.
    return anthropic.Anthropic(api_key=key, max_retries=2, timeout=120.0)


@dataclass(frozen=True, slots=True)
class AnthropicGenerator:
    """Drafts section prose. Restates facts; never derives them."""

    model: str = ""
    effort: str = ""
    max_tokens: int = 0

    @property
    def name(self) -> str:
        return self.model or settings.NARRATIVE_MODEL

    @property
    def available(self) -> bool:
        """Three independent conditions, reported as one boolean but logged apart."""
        if not settings.NARRATIVE_ENABLED:
            return False
        try:
            _client()
        except GenerationUnavailable as error:
            logger.info("narrative_provider_unavailable", reason=str(error))
            return False
        return True

    def complete(self, system: str, user: str, *, max_words: int) -> str:
        client = _client()
        try:
            response = client.beta.messages.create(
                model=self.model or settings.NARRATIVE_MODEL,
                max_tokens=self.max_tokens or settings.NARRATIVE_MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": user}],
                # Adaptive lets the model decide how much to think; effort is the
                # cost lever. Neither changes what it is *allowed* to assert.
                thinking={"type": "adaptive"},
                output_config={"effort": self.effort or settings.NARRATIVE_EFFORT},
                # A safety classifier may decline. Routing to a fallback keeps a
                # section from failing outright on a false positive — assessment
                # prose about vulnerabilities is exactly the adjacent-to-security
                # content that occasionally trips one.
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except Exception as error:  # noqa: BLE001 - narrowed and re-raised below
            raise _translate(error) from error

        # **Checked before `content` is read.** A refusal returns HTTP 200 with an
        # empty or partial content list, so indexing straight into it raises an
        # IndexError that looks like a bug rather than the policy decision it is.
        if response.stop_reason == "refusal":
            category = getattr(getattr(response, "stop_details", None), "category", None)
            raise GenerationUnavailable(
                f"the provider declined this section (category: {category}). The "
                "assessment still carries its findings from the scoring engine."
            )

        text = "".join(
            block.text for block in response.content if getattr(block, "type", "") == "text"
        )
        if not text.strip():
            raise GenerationUnavailable(
                f"the provider returned no text (stop_reason: {response.stop_reason})"
            )

        logger.info(
            "narrative_generated",
            model=response.model,
            stop_reason=response.stop_reason,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )
        return text.strip()


def _translate(error: Exception) -> Exception:
    """Map SDK errors onto one type the caller can act on.

    Matched by class rather than by message: the SDK defines a distinct exception
    per status precisely so callers do not string-match, and a message match
    breaks silently when the wording improves.
    """
    try:
        import anthropic
    except ImportError:  # pragma: no cover - unreachable from `complete`
        return error

    if isinstance(error, anthropic.NotFoundError):
        return GenerationUnavailable(
            f"model {settings.NARRATIVE_MODEL!r} was not found — check "
            "NARRATIVE_MODEL against the current model list"
        )
    if isinstance(error, anthropic.AuthenticationError):
        return GenerationUnavailable("ANTHROPIC_API_KEY was rejected")
    if isinstance(error, anthropic.RateLimitError):
        return GenerationUnavailable("provider rate limit reached; the SDK already retried")
    if isinstance(error, anthropic.APIConnectionError):
        return GenerationUnavailable("could not reach the provider")
    if isinstance(error, anthropic.APIStatusError):
        return GenerationUnavailable(f"provider returned {error.status_code}")
    return error


def active_generator() -> Any:
    """The generator this deployment should use.

    Resolved once at composition time rather than imported as a global, so a test
    can pass a different one and a deployment without a provider degrades to
    `NullGenerator` instead of raising.
    """
    from app.services.narrative.generator import NullGenerator

    candidate = AnthropicGenerator()
    return candidate if candidate.available else NullGenerator()
