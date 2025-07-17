"""Qubicly - Python client library for the Qubic protocol."""

from .qubic import QubicClient
from .types import (
    # Core types
    TickInfo,
    SystemInfo,
    
    # Asset types
    IssuedAssets,
    OwnedAssets,
    PossessedAssets,
    AssetIssuances,
    AssetOwnerships,
    AssetPossessions,
    AssetInfo,
    
    # Transaction types
    Transaction,
    Transactions,
    TransactionStatus,
    TickData,
    
    # Request/Response types
    RequestResponseHeader,
    RequestBody,
    ResponseBody,
    
    # Constants
    END_RESPONSE,
    NUMBER_OF_TRANSACTIONS_PER_TICK,
    ASSETS_DEPTH,
    NUMBER_OF_COMPUTORS,
)

__version__ = "0.1.0"
__author__ = "Friendwu"

__all__ = [
    "QubicClient",
    "TickInfo",
    "SystemInfo",
    "IssuedAssets",
    "OwnedAssets", 
    "PossessedAssets",
    "AssetIssuances",
    "AssetOwnerships",
    "AssetPossessions",
    "AssetInfo",
    "Transaction",
    "Transactions",
    "TransactionStatus",
    "TickData",
    "RequestResponseHeader",
    "RequestBody",
    "ResponseBody",
    "END_RESPONSE",
    "NUMBER_OF_TRANSACTIONS_PER_TICK",
    "ASSETS_DEPTH",
    "NUMBER_OF_COMPUTORS",
]
