# Installation

HEXSSL-CLI can be installed in two ways:
- via PyPI (recommended)
- from GitHub source (development version)

---

## Install from PyPI

    pip install hexssl-cli

After installation:

    hexssl-cli

---

## Install from GitHub (development version)

    git clone https://github.com/hexssl/hexssl-cli.git
    cd hexssl-cli
    pip install .

---

## Requirements

- Python 3.9 or newer
- pip
- Internet access for scanning

---

## Upgrade

    pip install --upgrade hexssl-cli

---

## Uninstall

    pip uninstall hexssl-cli

---

## Verify installation

    hexssl-cli hsts check example.com

If you see output, installation is correct.
