# SPDX-License-Identifier: Apache-2.0
# Packaging for the SecLoop SA-GRPO training subsystem.
"""Installable SA-GRPO training package (``training/src/open_r1``).

The upstream TRL revision is pinned by commit rather than vendored; the repository
never ships a copy of TRL.  Both git URLs below point at the upstream projects.
"""

from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup

_HERE = Path(__file__).parent
_README = _HERE / "README.md"

# Runtime dependencies.  The TRL pin is the exact upstream revision the SA-GRPO
# values were validated against; `trl==0.18.0` is the equivalent release.
_TRL_PIN = "trl @ git+https://github.com/huggingface/trl.git@1bca49515ecd5b85d16e68c42c76670e252e19f1"
_TRANSFORMERS_PIN = (
    "transformers @ git+https://github.com/huggingface/transformers.git@acdbe627e323dbc822f21499fead789b439cf45b"
)

install_requires = [
    "accelerate==1.4.0",
    "datasets>=3.2.0",
    "deepspeed==0.16.7",
    "peft>=0.14.0",
    "requests>=2.31.0",
    "torch==2.6.0",
    _TRANSFORMERS_PIN,
    _TRL_PIN,
    "wandb>=0.19.1",
]

extras = {
    "tests": ["pytest>=8.0.0"],
    "quality": ["ruff>=0.9.0"],
    # Only needed for `attn_implementation: flash_attention_2` or for the optional
    # vLLM generation server.  Both require a matching CUDA toolchain, so they are
    # kept out of the default install.
    "flash-attn": ["flash-attn>=2.7.0"],
    "vllm": ["vllm>=0.8.3"],
}

setup(
    name="secloop-training",
    version="0.1.0.dev0",
    description="SA-GRPO training subsystem for the SecLoop security-automation framework",
    long_description=_README.read_text(encoding="utf-8") if _README.is_file() else "",
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    package_dir={"": "src"},
    packages=find_packages("src"),
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.11",
    install_requires=install_requires,
    extras_require=extras,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
    ],
)
