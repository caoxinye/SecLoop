# SPDX-License-Identifier: Apache-2.0
"""Repository-wide pytest configuration.

The project contract requires the working tree to contain no ``__pycache__``
directories and no ``*.pyc`` files (see ``docs/INTERFACES.md`` section 12), and
``tests/check_repo_contract.py`` enforces exactly that.  Running the test suite
should therefore not dirty the tree, so bytecode caching is disabled for the
whole pytest process: every test module and every project module imported after
this point writes nothing.

**Known residual, documented rather than hidden:** pytest compiles *this file*
through its assertion-rewrite import hook *before* executing it, so the
rewriter's cache (``__pycache__/conftest.*.pyc``) lands on disk before the
assignment below can take effect.  Nothing inside this file can prevent that,
because the code runs too late.  For a genuinely clean tree, disable bytecode at
interpreter startup instead:

    PYTHONDONTWRITEBYTECODE=1 python -m pytest -q

That is why ``docs/quickstart.md`` shows the environment variable.  Either way
the working tree stays committable: ``__pycache__/`` is in ``.gitignore``, and
the contract checker fails the build if bytecode is ever present in the tree.

This is a performance setting only; it changes no behaviour.
"""

import sys

sys.dont_write_bytecode = True
