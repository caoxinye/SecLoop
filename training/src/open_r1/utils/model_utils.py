# SPDX-License-Identifier: Apache-2.0
"""Tokenizer helper for the training entry point."""

from __future__ import annotations

from typing import Any

from transformers import AutoTokenizer, PreTrainedTokenizer
from trl import ModelConfig

from ..configs import GRPOConfig

__all__ = ["DEFAULT_CHAT_TEMPLATE", "get_tokenizer"]

#: Fallback chat template for base models that ship none (kept from upstream open-r1).
DEFAULT_CHAT_TEMPLATE = (
    "{% for message in messages %}\n"
    "{% if message['role'] == 'user' %}\n"
    "{{ '<|user|>\n' + message['content'] + eos_token }}\n"
    "{% elif message['role'] == 'system' %}\n"
    "{{ '<|system|>\n' + message['content'] + eos_token }}\n"
    "{% elif message['role'] == 'assistant' %}\n"
    "{{ '<|assistant|>\n' + message['content'] + eos_token }}\n"
    "{% endif %}\n"
    "{% if loop.last and add_generation_prompt %}\n"
    "{{ '<|assistant|>' }}\n"
    "{% endif %}\n"
    "{% endfor %}"
)


def get_tokenizer(
    model_args: ModelConfig,
    training_args: GRPOConfig,
    auto_set_chat_template: bool = True,
) -> PreTrainedTokenizer:
    """Load the tokenizer for ``model_args.model_name_or_path``."""
    tokenizer = AutoTokenizer.from_pretrained(
        model_args.model_name_or_path,
        revision=model_args.model_revision,
        trust_remote_code=bool(getattr(model_args, "trust_remote_code", False)),
    )

    chat_template: Any = getattr(training_args, "chat_template", None)
    if chat_template is not None:
        tokenizer.chat_template = chat_template
    elif auto_set_chat_template and tokenizer.get_chat_template() is None:
        tokenizer.chat_template = DEFAULT_CHAT_TEMPLATE

    return tokenizer
