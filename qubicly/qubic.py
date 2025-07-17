import socket
import struct
from .types import * 
from contextlib import contextmanager

DEFAULT_TIMEOUT = 30

@contextmanager
def socket_timeout(sock, timeout):
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        yield
    finally:
        sock.settimeout(old_timeout)

class QubicClient:
    def __init__(self, node_ip: str, node_port: int, timeout=DEFAULT_TIMEOUT):
        self.node_ip = node_ip
        self.node_port = node_port
        self.timeout = timeout
        self.conn = socket.create_connection((node_ip, node_port), timeout=timeout)

    def close(self):
        self.conn.close()


    def get_peers(self):
        # TODO 
        pass


    def get_issued_assets(self, id: str):
        identity = Identity(id)
        pub_key = identity.to_pub_key(False)
        result = IssuedAssets()
        self._send_request(ISSUED_ASSETS_REQUEST, pub_key, result)
        
        return result


    def get_possessed_assets(self, id: str):
        identity = Identity(id)
        pub_key = identity.to_pub_key(False)
        result = PossessedAssets()
        self._send_request(POSSESSED_ASSETS_REQUEST, pub_key, result)
        
        return result


    def get_owned_assets(self, id: str):
        identity = Identity(id)
        pub_key = identity.to_pub_key(False)
        result = OwnedAssets()
        self._send_request(OWNED_ASSETS_REQUEST, pub_key, result)
        
        return result


    def get_identity(self, id: str):
        identity = Identity(id)
        pub_key = identity.to_pub_key(False)
        result = AddressInfo()
        self._send_request(BALANCE_TYPE_REQUEST, pub_key, result)
        
        return result


    def get_tick_info(self):
        result = TickInfo()
        self._send_request(CURRENT_TICK_INFO_REQUEST, None, result)
        
        return result
         

    def get_system_info(self):
        result = SystemInfo()
        self._send_request(SYSTEM_INFO_REQUEST, None, result)
        
        return result


    def get_tx_status(self, tick: int):
        request = struct.pack('<I', tick)
        result = TransactionStatus()
        self._send_request(TX_STATUS_REQUEST, request, result)
        
        return result


    def get_tick_data(self, tick_number: int):
        tick_info = self.get_tick_info()
        if tick_info.tick < tick_number:
            raise ValueError(f"Requested tick {tick_number} is in the future. Latest tick is: {tick_info.tick}")
        request = TickRequest(tick_number)
        result = TickData()
        self._send_request(TICK_DATA_REQUEST, request, result)
        
        return result


    def get_tick_transactions(self, tick_number: int):
        tick_data = self.get_tick_data(tick_number)
        nr_tx = sum(1 for digest in tick_data.transaction_digests if digest != [0] * 32)
        if nr_tx == 0:
            return Transactions()

        # Create request with fixed size transaction flags array
        transaction_flags = [0] * (NUMBER_OF_TRANSACTIONS_PER_TICK // 8)
        
        # Set first part to 0s
        for i in range((nr_tx + 7) // 8):
            transaction_flags[i] = 0
            
        # Set remaining to 1s
        for i in range((nr_tx + 7) // 8, NUMBER_OF_TRANSACTIONS_PER_TICK // 8):
            transaction_flags[i] = 1

        request = TickTransactionsRequest(tick_number, transaction_flags)
        result = Transactions()
        self._send_request(TICK_TRANSACTIONS_REQUEST, request, result)
        
        return result


    def send_raw_transaction(self, raw_tx: bytes):
        self._send_request(BROADCAST_TRANSACTION, raw_tx, None)


    def get_quorum_votes(self, tick_number: int):
        tick_info = self.get_tick_info()
        if tick_info.tick < tick_number:
            raise ValueError(f"Requested tick {tick_number} is in the future. Latest tick is: {tick_info.tick}")
        
        request = QuorumRequest(tick_number, [0] * ((NUMBER_OF_COMPUTORS + 7) // 8))
        result = QuorumVotes()
        self._send_request(QUORUM_TICK_REQUEST, request, result)
        
        return result
        

    def get_computors(self):
        result = Computors()
        self._send_request(COMPUTORS_REQUEST, None, result)
        
        return result
    

    def query_smart_contract(self, rcf: RequestContractFunction, request_data: bytes):
        result = SmartContractData()
        self._send_smart_contract_request(rcf, CONTRACT_FUNCTION_REQUEST, request_data, result)
        
        return result
        

    def get_asset_possessions_by_filter(self, issuer_identity: str, asset_name: str, owner_identity: str, possessor_identity: str, owner_contract: int, possessor_contract: int):
        request = self._create_get_asset_possessions_by_filter_request(
            AssetInformation(issuer_identity, asset_name),
            AssetHolderInformation(owner_identity, owner_contract),
            AssetHolderInformation(possessor_identity, possessor_contract)
        )
        result = AssetPossessions()
        self._send_request(REQUEST_ASSETS, request, result)
        
        return result
        

    def get_asset_ownerships_by_filter(self, issuer_identity: str, asset_name: str, owner_identity: str, owner_contract: int):
        request = self._create_get_asset_ownerships_by_filter_request(
            AssetInformation(issuer_identity, asset_name),
            AssetHolderInformation(owner_identity, owner_contract)
        )
        result = AssetOwnerships()
        self._send_request(REQUEST_ASSETS, request, result)
        
        return result
        

    def get_asset_issuances_by_filter(self, issuer_identity: str, asset_name: str):
        request = self._create_asset_issuances_by_filter_request(issuer_identity, asset_name)
        result = AssetIssuances()
        self._send_request(REQUEST_ASSETS, request, result)
        
        return result

    def get_asset_issuances_by_universe_index(self, index: int):
        result = AssetIssuances()
        self._get_asset_by_universe_index(index, result)
        
        return result

    def get_asset_ownerships_by_universe_index(self, index: int):
        result = AssetOwnerships()
        self._get_asset_by_universe_index(index, result)
        
        return result

    def get_asset_possessions_by_universe_index(self, index: int):
        result = AssetPossessions()
        self._get_asset_by_universe_index(index, result)
        
        return result

    
    def _send_request(self, request_type: int, request_data: RequestBody|bytes|None, dest=None):
        packet = self._serialize_request(request_type, request_data)
        with socket_timeout(self.conn, self.timeout):
            self.conn.sendall(packet)
            if dest is not None:
                return dest.decode(self.conn)  # Read response and decode
        
        return None


    def _serialize_request(self, request_type: int, request_data: RequestBody|bytes|None):
        if isinstance(request_data, bytes):
            serialized_req_data = request_data
        else:
            serialized_req_data = request_data.encode() if request_data else b''
        
        header = RequestResponseHeader()
        packet_header_size = 8  
        req_data_size = len(serialized_req_data) if serialized_req_data else 0
        packet_size = packet_header_size + req_data_size
        
        header.set_size(packet_size)
        if request_type == BROADCAST_TRANSACTION:
            header.zero_deja_vu()
        else:
            header.randomize_deja_vu()
        header.type = request_type
        
        serialized_header = header.encode()
        serialized_packet = serialized_header + (serialized_req_data or b'')
        
        return serialized_packet


    def _get_asset_by_universe_index(self, index: int, destination):
        request = RequestAssetsByUniverseIndex(ASSET_BY_UNIVERSE_INDEX, index)
        self._send_request(REQUEST_ASSETS, request, destination)


    def _send_smart_contract_request(self, rcf: RequestContractFunction, request_type, request_data: bytes, dest=None):
        packet = self._serialize_smart_contract_request(rcf, request_type, request_data)
        with socket_timeout(self.conn, self.timeout):
            self.conn.sendall(packet)
            if dest is not None:
                return dest.decode(self.conn.recv(4096))
        return None


    def _serialize_smart_contract_request(self, rcf: RequestContractFunction, request_type, request_data: bytes):
        serialized_rcf = rcf.encode()

        header = RequestResponseHeader()
        packet_header_size = 8  
        req_data_size = len(request_data) if request_data else 0
        packet_size = packet_header_size + len(serialized_rcf) + req_data_size
        
        header.set_size(packet_size)
        header.randomize_deja_vu()
        header.type = request_type
        
        serialized_header = header.encode()
        serialized_packet = serialized_header + serialized_rcf + (request_data or b'')
        
        return serialized_packet


    def _create_get_asset_ownerships_by_filter_request(self, asset_info: AssetInformation, owner_info: AssetHolderInformation):
        return self._create_by_filter_request(ASSET_OWNERSHIP_RECORDS, asset_info, owner_info, AssetHolderInformation("", 0))

    def _create_get_asset_possessions_by_filter_request(self, asset_info: AssetInformation, owner_info: AssetHolderInformation, possessor_info: AssetHolderInformation):
        return self._create_by_filter_request(ASSET_POSSESSION_RECORDS, asset_info, owner_info, possessor_info)
        

    def _create_by_filter_request(self, request_type: int, asset_info: AssetInformation, owner_info: AssetHolderInformation, possessor_info: AssetHolderInformation):
        issuer = bytes([0] * 32)
        if asset_info.identity:
            identity = Identity(asset_info.identity)
            issuer = identity.to_pub_key(False)
        if not asset_info.name:
            raise ValueError("asset name is required")

        name = asset_info.name.encode()[:8].ljust(8, b'\x00')

        owner = bytes([0] * 32)
        if owner_info.identity:
            identity = Identity(owner_info.identity)
            owner = identity.to_pub_key(False)
        
        possessor = bytes([0] * 32)
        if possessor_info.identity:
            identity = Identity(possessor_info.identity)
            possessor = identity.to_pub_key(False)
        
        request = RequestAssetsByFilter(
            request_type=request_type,
            flags=self._get_flags(owner_info, possessor_info),
            ownership_managing_contract=owner_info.contract,
            possession_managing_contract=possessor_info.contract,
            issuer=issuer,
            asset_name=name,
            owner=owner,
            possessor=possessor
        )
        return request
    

    def _get_flags(self, owner_info: AssetHolderInformation, possessor_info: AssetHolderInformation):
        flags = 0
        if not owner_info.identity:
            flags |= FLAG_ANY_OWNER
        if not possessor_info.identity:
            flags |= FLAG_ANY_POSSESSOR
        if owner_info.contract == 0:
            flags |= FLAG_ANY_OWNER_CONTRACT
        if possessor_info.contract == 0:
            flags |= FLAG_ANY_POSSESSOR_CONTRACT
        return flags
        

    def _create_asset_issuances_by_filter_request(self, issuer_identity: str, asset_name: str):
        flags = 0
        issuer = bytes([0] * 32)
        if not issuer_identity:
            flags |= FLAG_ANY_ISSUER
        else:
            identity = Identity(issuer_identity)
            issuer = identity.to_pub_key(False)
        name = asset_name.encode()[:8].ljust(8, b'\x00')
        if not asset_name:
            flags |= FLAG_ANY_ASSET_NAME
        request = RequestAssetsByFilter(
            request_type=ASSET_ISSUANCE_RECORDS,
            flags=flags,
            ownership_managing_contract=0,
            possession_managing_contract=0,
            issuer=issuer,
            asset_name=name,
            owner=bytes([0] * 32),
            possessor=bytes([0] * 32)
        )
        return request