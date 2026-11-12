# SPDX-License-Identifier: Apache-2.0
"""Vendor-neutral, OpenAI-compatible LLM client shared by the evaluation and training paths.

The canonical import for both the agent and ``training/src/open_r1/rewards.py`` is::

    from agent.llm.llm_interface import get_llm_client

This package ``__init__`` deliberately re-exports nothing: importing
``agent.llm.llm_interface`` as a module (``python -m agent.llm.llm_interface --check``,
INTERFACES §7.2) must not pre-import the submodule, and importing the package must not drag
in the HTTP dependency.
"""
