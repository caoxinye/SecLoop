# SPDX-License-Identifier: Apache-2.0
"""SecLoop LLM agent (paper §II-B): summarised IDS alerts -> defence strategy -> SOC round.

Entry points:

* ``python -m agent.main`` — the closed-loop CLI (see :mod:`agent.main`).
* :func:`agent.llm.llm_interface.get_llm_client` — the LLM client shared with the
  training path (INTERFACES §7).
* :func:`agent.tools.security_tools.create_security_tools` — the tool registry shared with
  the training path (INTERFACES §6).
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
