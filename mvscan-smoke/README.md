## Install

```
brew install uv
uv python install 3.10
uv venv --python 3.10
source .venv/bin/activate
```

To install MV-Scan and the frozen dependencies, from `mvscan-smoke`:

```
uv pip install -e .
uv pip install solc-select
```

Verify versions match:

```
python --version
uv pip show slither-analyzer
uv pip show crytic-compile
```

You should see:

```
Python 3.10.x
slither-analyzer 0.11.3
crytic-compile 0.3.11
```

Install Solidity `0.8.20`:

```
solc-select install 0.8.20
solc-select use 0.8.20
solc --version
```
