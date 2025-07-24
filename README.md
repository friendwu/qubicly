# Qubicly

A Python client library for the Qubic protocol, providing easy access to Qubic network functionality including transactions, assets, and system information.

## Installation

~~pip install qubicly~~

```bash
pip install git+https://github.com/friendwu/qubicly.git@master

```

## Quick Start

```python
from qubicly import QubicClient

# Connect to a Qubic node
client = QubicClient("45.152.160.28", 21841)

# Get current tick information
tick_info = client.get_tick_info()
print(f"Current tick: {tick_info.tick}")

# Get system information
system_info = client.get_system_info()
print(f"Epoch: {system_info.epoch}")

# Close connection
client.close()
```
