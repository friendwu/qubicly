import random
import struct
import socket
import json

# --- Protocol-specific constants ---
EXCHANGE_PUBLIC_PEERS = 0
BROADCAST_COMPUTORS = 2
QUORUM_TICK_RESPONSE = 3
QUORUM_TICK_REQUEST = 14
BROADCAST_FUTURE_TICK_DATA = 8
COMPUTORS_REQUEST = 11
TICK_DATA_REQUEST = 16
CURRENT_TICK_INFO_REQUEST = 27
CURRENT_TICK_INFO_RESPONSE = 28
TICK_TRANSACTIONS_REQUEST = 29
BALANCE_TYPE_REQUEST = 31
BALANCE_TYPE_RESPONSE = 32
END_RESPONSE = 35
ISSUED_ASSETS_REQUEST = 36
ISSUED_ASSETS_RESPONSE = 37
OWNED_ASSETS_REQUEST = 38
OWNED_ASSETS_RESPONSE = 39
POSSESSED_ASSETS_REQUEST = 40
POSSESSED_ASSETS_RESPONSE = 41
CONTRACT_FUNCTION_REQUEST = 42
CONTRACT_FUNCTION_RESPONSE = 43
SYSTEM_INFO_REQUEST = 46
SYSTEM_INFO_RESPONSE = 47
BROADCAST_TRANSACTION = 24
TX_STATUS_REQUEST = 201
TX_STATUS_RESPONSE = 202
REQUEST_ASSETS = 52
RESPOND_ASSETS = 53

# Asset filter constants
ASSET_ISSUANCE_RECORDS = 0
ASSET_OWNERSHIP_RECORDS = 1
ASSET_POSSESSION_RECORDS = 2
ASSET_BY_UNIVERSE_INDEX = 3

# Flag constants
FLAG_ANY_ISSUER = 0b10
FLAG_ANY_ASSET_NAME = 0b100
FLAG_ANY_OWNER = 0b1000
FLAG_ANY_OWNER_CONTRACT = 0b10000
FLAG_ANY_POSSESSOR = 0b100000
FLAG_ANY_POSSESSOR_CONTRACT = 0b1000000

NUMBER_OF_TRANSACTIONS_PER_TICK = 1024
NUMBER_OF_COMPUTORS = 676
ASSETS_DEPTH = 24  

class RequestBody:
    def encode(self) -> bytes:
        raise NotImplementedError
    

class ResponseBody:
    def decode(self, conn: socket.socket):
        raise NotImplementedError


class RequestResponseHeader:
    def __init__(self):
        self.size = [0, 0, 0]  # 3 bytes
        self.type = 0          # 1 byte
        self.deja_vu = 0       # 4 bytes

    def set_size(self, size: int):
        self.size[0] = size & 0xFF
        self.size[1] = (size >> 8) & 0xFF
        self.size[2] = (size >> 16) & 0xFF

    def get_size(self) -> int:
        size = self.size[0] | (self.size[1] << 8) | (self.size[2] << 16)
        return size & 0xFFFFFF

    def zero_deja_vu(self):
        self.deja_vu = 0

    def randomize_deja_vu(self):
        self.deja_vu = random.randint(1, 0xFFFFFFFF)
        if self.deja_vu == 0:
            self.deja_vu = 1

    def is_deja_vu_zero(self):
        return self.deja_vu == 0

    def encode(self) -> bytes:
        # 3 bytes size, 1 byte type, 4 bytes deja_vu
        return bytes(self.size) + struct.pack('<B', self.type) + struct.pack('<I', self.deja_vu)

    def decode(self, conn, expected_type):
        while True:
            # Read header (8 bytes) - big endian for header
            header_data = must_recv(conn, 8)
            
            self.size = list(header_data[0:3])
            self.type = header_data[3]
            self.deja_vu = struct.unpack('>I', header_data[4:8])[0]

            if self.type == END_RESPONSE:
                break
            
            if self.type == 0 or self.type != expected_type:
                print(f"Invalid header type, expected {expected_type}, found {self.type}")
                ignore_size = self.get_size() - 8  # header size is 8 bytes
                if ignore_size > 0:
                    must_recv(conn, ignore_size)
                continue
            break

class IssuedAssetData:
    def __init__(self):
        self.public_key = b''  # [32]byte
        self.type = 0          # byte
        self.name = b''        # [7]int8
        self.number_of_decimal_places = 0  # int8
        self.unit_of_measurement = b''     # [7]int8

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'public_key': self.public_key.hex(),
            'type': self.type, 
            'name': self.name.decode('utf-8'),
            'number_of_decimal_places': self.number_of_decimal_places,
            'unit_of_measurement': self.unit_of_measurement.decode('utf-8')
        }

    def decode(self, conn):
        # Read all fields at once: 32 bytes public key + 1 byte type + 7 bytes name + 1 byte decimal + 7 bytes unit = 48 bytes
        data = must_recv(conn, 48)
        if len(data) < 48:
            raise ValueError("Failed to read complete IssuedAssetData")
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields: type(B) + name(7s) + decimal(b) + unit(7s)
        self.type, self.name, self.number_of_decimal_places, self.unit_of_measurement = struct.unpack('<B7sb7s', data[32:48])

class OwnedAssetData:
    def __init__(self):
        self.public_key = bytes([0] * 32)  # [32]byte
        self.type = 0  # byte
        self.padding = bytes([0])  # [1]int8
        self.managing_contract_index = 0  # uint16
        self.issuance_index = 0  # uint32
        self.number_of_units = 0  # int64
        self.issued_asset = IssuedAssetData()  # IssuedAssetData

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'public_key': self.public_key.hex(),
            'type': self.type, 
            'padding': self.padding.hex(),
            'managing_contract_index': self.managing_contract_index,
            'issuance_index': self.issuance_index,
            'number_of_units': self.number_of_units,
            'issued_asset': self.issued_asset.__dict__()
        }

    def decode(self, conn):
        # Read main fields: 32 bytes public key + 1 byte type + 1 byte padding + 2 bytes contract + 4 bytes issuance + 8 bytes units = 48 bytes
        data = must_recv(conn, 48)
        if len(data) < 48:
            raise ValueError("Failed to read OwnedAssetData main fields")
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields: type(B) + padding(s) + contract(H) + issuance(I) + units(q)
        self.type, self.padding, self.managing_contract_index, self.issuance_index, self.number_of_units = struct.unpack('<BsHIq', data[32:48])
        
        # Decode nested issued asset
        self.issued_asset.decode(conn)

class AssetInfo:
    def __init__(self):
        self.tick = 0           # uint32
        self.universe_index = 0 # uint32
        self.siblings = []      # [AssetsDepth][32]byte

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'tick': self.tick,
            'universe_index': self.universe_index,
            'siblings': [sibling.hex() for sibling in self.siblings]
        }

    def decode(self, conn):
        header_data = must_recv(conn, 8)
        
        self.tick, self.universe_index = struct.unpack('<II', header_data)
        
        # Read siblings array: ASSETS_DEPTH (24) entries of 32 bytes each = 768 bytes
        siblings_size = ASSETS_DEPTH * 32
        siblings_data = must_recv(conn, siblings_size)
        if len(siblings_data) < siblings_size:
            raise ValueError("Failed to read AssetInfo siblings")
        
        # Split into 32-byte chunks
        self.siblings = []
        for i in range(0, siblings_size, 32):
            sibling = siblings_data[i:i+32]
            self.siblings.append(sibling)

class IssuedAsset:
    def __init__(self):
        self.data = IssuedAssetData()
        self.info = AssetInfo()

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'data': self.data.__dict__(),
            'info': self.info.__dict__()
        }

class OwnedAsset:
    def __init__(self):
        self.data = OwnedAssetData()
        self.info = AssetInfo()

class IssuedAssets(ResponseBody):
    def __init__(self):
        self.assets = [] # [IssuedAsset]
    
    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'assets': [asset.__dict__() for asset in self.assets]
        }
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, ISSUED_ASSETS_RESPONSE)
            
            if header.type == END_RESPONSE:
                break

            # Read issued asset data
            issued_asset_data = IssuedAssetData()
            issued_asset_data.decode(conn)
            
            # Read asset info
            asset_info = AssetInfo() 
            asset_info.decode(conn)
            
            issued_asset = IssuedAsset()
            issued_asset.data = issued_asset_data
            issued_asset.info = asset_info
            
            self.assets.append(issued_asset)


class PossessedAssetData:
    def __init__(self):
        self.public_key = bytes([0] * 32)  # [32]byte
        self.type = 0  # byte
        self.padding = bytes([0])  # [1]int8
        self.managing_contract_index = 0  # uint16
        self.issuance_index = 0  # uint32
        self.number_of_units = 0  # int64
        self.owned_asset = OwnedAssetData()  # OwnedAssetData

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'public_key': self.public_key.hex(),
            'type': self.type,
            'padding': self.padding.hex(),
            'managing_contract_index': self.managing_contract_index,
            'issuance_index': self.issuance_index,
            'number_of_units': self.number_of_units,
            'owned_asset': self.owned_asset.__dict__()
        }

    def decode(self, conn):
        # Read all fields: 32 bytes public key + 1 byte type + 1 byte padding + 2 bytes contract + 4 bytes issuance + 8 bytes units = 48 bytes
        data = must_recv(conn, 48)
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields
        (self.type, self.padding, self.managing_contract_index, 
         self.issuance_index, self.number_of_units) = struct.unpack('<BsHIq', data[32:48])
        
        # Decode owned asset
        self.owned_asset.decode(conn)

class PossessedAsset:
    def __init__(self):
        self.data = PossessedAssetData()
        self.info = AssetInfo()
    
    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'data': self.data.__dict__(),
            'info': self.info.__dict__()
        }

class PossessedAssets(ResponseBody):
    def __init__(self):
        self.assets = []
    
    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'assets': [asset.__dict__() for asset in self.assets]
        }
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, POSSESSED_ASSETS_RESPONSE)
            
            if header.type == END_RESPONSE:
                break
                
            # Read possessed asset data
            possessed_asset_data = PossessedAssetData()
            possessed_asset_data.decode(conn)
            
            # Read asset info
            asset_info = AssetInfo() 
            asset_info.decode(conn)
            
            possessed_asset = PossessedAsset()
            possessed_asset.data = possessed_asset_data
            possessed_asset.info = asset_info
            
            self.assets.append(possessed_asset)

class OwnedAssets(ResponseBody):
    def __init__(self):
        self.assets = []
    
    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'assets': [asset.__dict__() for asset in self.assets]
        }
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, OWNED_ASSETS_RESPONSE)
            
            if header.type == END_RESPONSE:
                break
                
            # Read owned asset data
            owned_asset_data = OwnedAssetData()
            owned_asset_data.decode(conn)
            
            # Read asset info
            asset_info = AssetInfo() 
            asset_info.decode(conn)
            
            owned_asset = OwnedAsset()
            owned_asset.data = owned_asset_data
            owned_asset.info = asset_info
            
            self.assets.append(owned_asset)

class AssetIssuanceData:
    def __init__(self):
        self.public_key = bytes([0] * 32)  # [32]byte
        self.type = 0  # byte
        self.name = bytes([0] * 7)  # [7]int8
        self.number_of_decimal_places = 0  # int8
        self.unit_of_measurement = bytes([0] * 7)  # [7]int8

    def decode(self, conn):
        # Read all fields at once: 32 bytes public key + 1 byte type + 7 bytes name + 1 byte decimal + 7 bytes unit = 48 bytes
        data = must_recv(conn, 48)
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields: type(B) + name(7s) + decimal(b) + unit(7s)
        self.type, self.name, self.number_of_decimal_places, self.unit_of_measurement = struct.unpack('<B7sb7s', data[32:48])

class AssetIssuance:
    def __init__(self):
        self.asset = AssetIssuanceData()
        self.tick = 0  # uint32
        self.universe_index = 0  # uint32

class AssetOwnershipData:
    def __init__(self):
        self.public_key = bytes([0] * 32)  # [32]byte
        self.type = 0  # byte
        self.padding = bytes([0])  # [1]int8
        self.managing_contract_index = 0  # uint16
        self.issuance_index = 0  # uint32
        self.number_of_units = 0  # int64

    def decode(self, conn):
        # Read all fields: 32 bytes public key + 1 byte type + 1 byte padding + 2 bytes contract + 4 bytes issuance + 8 bytes units = 48 bytes
        data = must_recv(conn, 48)
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields: type(B) + padding(s) + contract(H) + issuance(I) + units(q)
        self.type, self.padding, self.managing_contract_index, self.issuance_index, self.number_of_units = struct.unpack('<BsHIq', data[32:48])

class AssetOwnership:
    def __init__(self):
        self.asset = AssetOwnershipData()
        self.tick = 0  # uint32
        self.universe_index = 0  # uint32

class AssetPossessionData:
    def __init__(self):
        self.public_key = bytes([0] * 32)  # [32]byte
        self.type = 0  # byte
        self.padding = bytes([0])  # [1]int8
        self.managing_contract_index = 0  # uint16
        self.ownership_index = 0  # uint32
        self.number_of_units = 0  # int64

    def decode(self, conn):
        # Read all fields: 32 bytes public key + 1 byte type + 1 byte padding + 2 bytes contract + 4 bytes ownership + 8 bytes units = 48 bytes
        data = must_recv(conn, 48)
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields: type(B) + padding(s) + contract(H) + ownership(I) + units(q)
        self.type, self.padding, self.managing_contract_index, self.ownership_index, self.number_of_units = struct.unpack('<BsHIq', data[32:48])

class AssetPossession:
    def __init__(self):
        self.asset = AssetPossessionData()
        self.tick = 0  # uint32
        self.universe_index = 0  # uint32

class AssetPossessions(ResponseBody):
    def __init__(self):
        self.possessions = []
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, RESPOND_ASSETS)
            
            if header.type == END_RESPONSE:
                break
                
            # Read asset possession data
            asset_possession_data = AssetPossessionData()
            asset_possession_data.decode(conn)
            
            # Read tick (4 bytes)
            data = must_recv(conn, 4)
            tick = struct.unpack('<I', data)[0]
            
            # Read universe index (4 bytes)
            data = must_recv(conn, 4)
            universe_index = struct.unpack('<I', data)[0]
            
            asset_possession = AssetPossession()
            asset_possession.asset = asset_possession_data
            asset_possession.tick = tick
            asset_possession.universe_index = universe_index
            
            self.possessions.append(asset_possession)

class AssetOwnerships(ResponseBody):
    def __init__(self):
        self.ownerships = []
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, RESPOND_ASSETS)
            
            if header.type == END_RESPONSE:
                break
                
            # Read asset ownership data
            asset_ownership_data = AssetOwnershipData()
            asset_ownership_data.decode(conn)
            
            # Read tick (4 bytes)
            data = must_recv(conn, 4)
            tick = struct.unpack('<I', data)[0]
            
            # Read universe index (4 bytes)
            data = must_recv(conn, 4)
            universe_index = struct.unpack('<I', data)[0]
            
            asset_ownership = AssetOwnership()
            asset_ownership.asset = asset_ownership_data
            asset_ownership.tick = tick
            asset_ownership.universe_index = universe_index
            
            self.ownerships.append(asset_ownership)

class AssetIssuances(ResponseBody):
    def __init__(self):
        self.issuances = []
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, RESPOND_ASSETS)
            
            if header.type == END_RESPONSE:
                break
                
            # Read issued asset data
            issued_asset_data = AssetIssuanceData()
            issued_asset_data.decode(conn)
            
            # Read tick (4 bytes)
            data = must_recv(conn, 4)
            tick = struct.unpack('<I', data)[0]
            
            # Read universe index (4 bytes)
            data = must_recv(conn, 4)
            universe_index = struct.unpack('<I', data)[0]
            
            asset_issuance = AssetIssuance()
            asset_issuance.asset = issued_asset_data
            asset_issuance.tick = tick
            asset_issuance.universe_index = universe_index
            
            self.issuances.append(asset_issuance)


class PublicPeers(ResponseBody):
    def __init__(self):
        self.peers = []
    
    def decode(self, conn):
        header = RequestResponseHeader()
        header.decode(conn, EXCHANGE_PUBLIC_PEERS)

        if header.type == END_RESPONSE:
            return
        
        # Read 4 peer IP addresses (4 bytes each)
        peers_data = must_recv(conn, 16)  # 4 peers * 4 bytes
        
        # Process each peer IP
        for i in range(0, 16, 4):
            peer_bytes = peers_data[i:i+4]
            if peer_bytes == bytes([0] * 4):
                continue
                
            ip = socket.inet_ntoa(peer_bytes)
            if ip:
                self.peers.append(ip)

class AddressData:
    def __init__(self):
        self.public_key = bytes([0] * 32)  # [32]byte
        self.incoming_amount = 0  # int64
        self.outgoing_amount = 0  # int64
        self.number_of_incoming_transfers = 0  # uint32
        self.number_of_outgoing_transfers = 0  # uint32
        self.latest_incoming_transfer_tick = 0  # uint32
        self.latest_outgoing_transfer_tick = 0  # uint32

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'public_key': self.public_key.hex(),
            'incoming_amount': self.incoming_amount,
            'outgoing_amount': self.outgoing_amount,
            'number_of_incoming_transfers': self.number_of_incoming_transfers,
            'number_of_outgoing_transfers': self.number_of_outgoing_transfers,
            'latest_incoming_transfer_tick': self.latest_incoming_transfer_tick,
            'latest_outgoing_transfer_tick': self.latest_outgoing_transfer_tick
        }

    def decode(self, conn):
        # Read all fields: 32 bytes public key + 8+8 bytes amounts + 4*4 bytes counters/ticks = 64 bytes
        data = must_recv(conn, 64)
        
        # Extract public key (32 bytes)
        self.public_key = data[0:32]
        
        # Unpack remaining fields
        (self.incoming_amount, self.outgoing_amount,
         self.number_of_incoming_transfers, self.number_of_outgoing_transfers,
         self.latest_incoming_transfer_tick, self.latest_outgoing_transfer_tick) = struct.unpack('<qqIIII', data[32:])

class AddressInfo(ResponseBody):
    SPECTRUM_DEPTH = 24  # SpectrumDepth constant
    
    def __init__(self):
        self.address_data = AddressData()
        self.tick = 0  # uint32
        self.spectrum_index = 0  # int32
        self.siblings = []  # [SPECTRUM_DEPTH][32]byte

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'address_data': self.address_data.__dict__(),
            'tick': self.tick,
            'spectrum_index': self.spectrum_index,
            'siblings': [sibling.hex() for sibling in self.siblings]
        }

    def decode(self, conn):
        header = RequestResponseHeader()
        header.decode(conn, BALANCE_TYPE_RESPONSE)

        if header.type == END_RESPONSE:
            return

        # Decode address data
        self.address_data.decode(conn)
        
        # Read tick and spectrum_index (8 bytes total)
        data = must_recv(conn, 8)
        self.tick, self.spectrum_index = struct.unpack('<Ii', data)
        
        # Read siblings array: SPECTRUM_DEPTH entries of 32 bytes each = 768 bytes
        siblings_size = self.SPECTRUM_DEPTH * 32
        siblings_data = must_recv(conn, siblings_size)
        
        # Split into 32-byte chunks
        self.siblings = []
        for i in range(0, siblings_size, 32):
            sibling = siblings_data[i:i+32]
            self.siblings.append(sibling)

class TickInfo(ResponseBody):
    def __init__(self):
        self.tick_duration = 0  # uint16
        self.epoch = 0          # uint16
        self.tick = 0           # uint32
        self.number_of_aligned_votes = 0    # uint16
        self.number_of_misaligned_votes = 0 # uint16
        self.initial_tick = 0   # uint32

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'tick_duration': self.tick_duration,
            'epoch': self.epoch, 
            'tick': self.tick,
            'number_of_aligned_votes': self.number_of_aligned_votes,
            'number_of_misaligned_votes': self.number_of_misaligned_votes,
            'initial_tick': self.initial_tick
        }

    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, CURRENT_TICK_INFO_RESPONSE)

            if header.type == END_RESPONSE:
                return  
            
            # Read tick info payload (16 bytes) - little endian for data
            payload_size = 16
            payload = must_recv(conn, payload_size)
                
            (
                self.tick_duration,
                self.epoch,
                self.tick,
                self.number_of_aligned_votes,
                self.number_of_misaligned_votes,
                self.initial_tick
            ) = struct.unpack('<HHIHHI', payload)
            
            break

    
class SystemInfo(ResponseBody):
    def __init__(self):
        self.version = 0  # int16

        self.epoch = 0  # uint16
        self.tick = 0  # uint32
        self.initial_tick = 0  # uint32
        self.latest_created_tick = 0  # uint32
        self.initial_millisecond = 0  # uint16
        self.initial_second = 0  # uint8
        self.initial_minute = 0  # uint8
        self.initial_hour = 0  # uint8
        self.initial_day = 0  # uint8
        self.initial_month = 0  # uint8
        self.initial_year = 0  # uint8
        
        self.number_of_entities = 0  # uint32
        self.number_of_transactions = 0  # uint32
        
        self.random_mining_seed = b""  # 32 bytes
        self.solution_threshold = 0  # int32
        
        self.total_spectrum_amount = 0  # uint64
        self.current_entity_balance_dust_threshold = 0  # uint64
        self.target_tick_vote_signature = 0  # uint32
        
        self.reserve0 = 0  # uint64
        self.reserve1 = 0  # uint64
        self.reserve2 = 0  # uint64
        self.reserve3 = 0  # uint64
        self.reserve4 = 0  # uint64

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'version': self.version,
            'epoch': self.epoch,
            'tick': self.tick,
            'initial_tick': self.initial_tick,
            'latest_created_tick': self.latest_created_tick,
            'initial_millisecond': self.initial_millisecond,
            'initial_second': self.initial_second, 
            'initial_minute': self.initial_minute,
            'initial_hour': self.initial_hour,
            'initial_day': self.initial_day,
            'initial_month': self.initial_month,
            'initial_year': self.initial_year,
            'number_of_entities': self.number_of_entities,
            'number_of_transactions': self.number_of_transactions,
            'random_mining_seed': self.random_mining_seed.hex(),
            'solution_threshold': self.solution_threshold,
            'total_spectrum_amount': self.total_spectrum_amount,
            'current_entity_balance_dust_threshold': self.current_entity_balance_dust_threshold,
            'target_tick_vote_signature': self.target_tick_vote_signature,
        }

    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, SYSTEM_INFO_RESPONSE)
            
            if header.type == END_RESPONSE:
                return
            
            # Read system info payload (128 bytes) - little endian for data
            payload_size = 128
            payload = must_recv(conn, payload_size)
            
            # Parse all fields in one go
            # Format: hHIIIH6BII + 32s + iQQIQQQQQ = 128 bytes total
            (
                self.version,
                self.epoch,
                self.tick,
                self.initial_tick,
                self.latest_created_tick,
                self.initial_millisecond,
                self.initial_second,
                self.initial_minute,
                self.initial_hour,
                self.initial_day,
                self.initial_month,
                self.initial_year,
                self.number_of_entities,
                self.number_of_transactions,
                self.random_mining_seed,
                self.solution_threshold,
                self.total_spectrum_amount,
                self.current_entity_balance_dust_threshold,
                self.target_tick_vote_signature,
                self.reserve0,
                self.reserve1,
                self.reserve2,
                self.reserve3,
                self.reserve4
            ) = struct.unpack('<hHIIIH6BII32siQQIQQQQQ', payload)
            break 


class Transaction:
    def __init__(self):
        self.source_public_key = bytes([0] * 32)      # [32]byte
        self.destination_public_key = bytes([0] * 32) # [32]byte
        self.amount = 0                               # int64
        self.tick = 0                                 # uint32
        self.input_type = 0                           # uint16
        self.input_size = 0                           # uint16
        self.input = b''                              # []byte
        self.signature = bytes([0] * 64)              # [64]byte

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)

    def __dict__(self):
        return {
            'source_public_key': self.source_public_key.hex(),
            'destination_public_key': self.destination_public_key.hex(),
            'amount': self.amount,
            'tick': self.tick,
            'input_type': self.input_type,
        }

    def decode(self, conn):
        # Read fixed-size fields: 32 + 32 + 8 + 4 + 2 + 2 = 80 bytes
        fixed_data = must_recv(conn, 80)
        
        # Extract public keys (64 bytes total)
        self.source_public_key = fixed_data[0:32]
        self.destination_public_key = fixed_data[32:64]
        
        # Unpack remaining fixed fields: amount(q) + tick(I) + input_type(H) + input_size(H)
        self.amount, self.tick, self.input_type, self.input_size = struct.unpack('<qIHH', fixed_data[64:80])
        
        # Read variable-size input data
        if self.input_size > 0:
            self.input = must_recv(conn, self.input_size)
        
        # Read signature (64 bytes)
        self.signature = must_recv(conn, 64)

    def encode(self) -> bytes:
        """Encode transaction to binary format (MarshallBinary equivalent)"""
        data = b''
        
        # Source and destination public keys (32 bytes each)
        data += self.source_public_key
        data += self.destination_public_key
        
        # Pack fixed fields in little-endian
        data += struct.pack('<qIHH', self.amount, self.tick, self.input_type, self.input_size)
        
        # Variable input data
        data += self.input
        
        # Signature (64 bytes)
        data += self.signature
        
        return data

    def get_unsigned_digest(self):
        """Get digest of transaction without signature"""
        serialized = self.encode()
        # Remove signature (last 64 bytes) for unsigned digest
        unsigned_data = serialized[:-64]
        return self._k12_hash(unsigned_data)

    def digest(self):
        """Get full digest of transaction including signature"""
        serialized = self.encode()
        return self._k12_hash(serialized)

    def _k12_hash(self, data: bytes) -> bytes:
        """K12 hash implementation (placeholder - needs actual K12 implementation)"""
        import hashlib
        # TODO: Replace with actual K12 hash implementation
        # For now using SHA256 as placeholder
        return hashlib.sha256(data).digest()

class TransactionStatus(ResponseBody):
    def __init__(self):
        self.current_tick_of_node = 0     # uint32
        self.tick = 0                     # uint32
        self.tx_count = 0                 # uint32
        self.money_flew = b''             # [(NumberOfTransactionsPerTick + 7) / 8]byte
        self.transaction_digests = []     # [][32]byte

    def decode(self, conn):
        header = RequestResponseHeader()
        header.decode(conn, TX_STATUS_RESPONSE)

        if header.type == END_RESPONSE:
            return

        # Read fixed fields (12 bytes): current_tick(I) + tick(I) + tx_count(I)
        fixed_data = must_recv(conn, 12)
        self.current_tick_of_node, self.tick, self.tx_count = struct.unpack('<III', fixed_data)

        # Read money_flew array: (NUMBER_OF_TRANSACTIONS_PER_TICK + 7) / 8 bytes = 128 bytes
        money_flew_size = (NUMBER_OF_TRANSACTIONS_PER_TICK + 7) // 8
        self.money_flew = must_recv(conn, money_flew_size)


        # Read transaction digests
        digest_size = self.tx_count * 32  # Each digest is 32 bytes
        if digest_size > 0:
            digests_data = must_recv(conn, digest_size)
            self.transaction_digests = [digests_data[i:i+32] for i in range(0, digest_size, 32)]

class Transactions(ResponseBody):
    def __init__(self):
        self.transactions = []
    
    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'transactions': [t.__dict__() for t in self.transactions]
        }

    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, BROADCAST_TRANSACTION)
            
            if header.type == END_RESPONSE:
                break
                
            # Read transaction
            transaction = Transaction()
            transaction.decode(conn)
            
            self.transactions.append(transaction)

class TickData(ResponseBody):
    def __init__(self):
        self.computor_index = 0      # uint16
        self.epoch = 0               # uint16 
        self.tick = 0               # uint32
        self.millisecond = 0        # uint16
        self.second = 0             # uint8
        self.minute = 0             # uint8
        self.hour = 0               # uint8
        self.day = 0                # uint8
        self.month = 0              # uint8
        self.year = 0               # uint8
        self.timelock = bytes([0] * 32)  # [32]byte
        self.transaction_digests = []  # [NUMBER_OF_TRANSACTIONS_PER_TICK][32]byte
        self.contract_fees = []      # [1024]int64
        self.signature = bytes([0] * 64)  # [64]byte

    def decode(self, conn):
        header = RequestResponseHeader()
        header.decode(conn, BROADCAST_FUTURE_TICK_DATA)
        
        if header.type == END_RESPONSE:
            return
            
        # Read fixed fields in one recv
        fixed_data = must_recv(conn, 16)  # 2+2+4+2+1+1+1+1+1+1 = 16 bytes
        if len(fixed_data) < 16:
            raise ValueError("Failed to read tick data fixed fields")
            
        (self.computor_index, self.epoch, self.tick, self.millisecond, 
         self.second, self.minute, self.hour, self.day, self.month, self.year) = struct.unpack('<HHIHBBBBBB', fixed_data)

        self.timelock = must_recv(conn, 32)
        digest_size = NUMBER_OF_TRANSACTIONS_PER_TICK * 32
        digests_data = must_recv(conn, digest_size)
        self.transaction_digests = [digests_data[i:i+32] for i in range(0, digest_size, 32)]

        fees_data = must_recv(conn, NUMBER_OF_TRANSACTIONS_PER_TICK * 8)
        self.contract_fees = list(struct.unpack(f'<{NUMBER_OF_TRANSACTIONS_PER_TICK}q', fees_data))

        self.signature = must_recv(conn, 64)

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'computor_index': self.computor_index,
            'epoch': self.epoch,
            'tick': self.tick,
            'millisecond': self.millisecond,
            'second': self.second,
            'minute': self.minute,
            'hour': self.hour,
            'day': self.day,
            'month': self.month,
            'year': self.year,
            'timelock': self.timelock.hex(),
            'transaction_digests': [d.hex() for d in self.transaction_digests if d != [0] * 32],
            'contract_fees': self.contract_fees,
            'signature': self.signature.hex()
        }


    def is_empty(self):
        """Check if tick data is empty"""
        return (self.computor_index == 0 and
                self.epoch == 0 and 
                self.tick == 0 and
                self.millisecond == 0 and
                self.second == 0 and
                self.minute == 0 and
                self.hour == 0 and
                self.day == 0 and
                self.month == 0 and
                self.year == 0 and
                self.timelock == bytes([0] * 32) and
                not self.transaction_digests and
                not self.contract_fees and
                self.signature == bytes([0] * 64))

class QuorumTickVote:
    def __init__(self):
        self.computor_index = 0  # uint16
        self.epoch = 0  # uint16
        self.tick = 0  # uint32
        
        self.millisecond = 0  # uint16
        self.second = 0  # uint8
        self.minute = 0  # uint8
        self.hour = 0  # uint8
        self.day = 0  # uint8
        self.month = 0  # uint8
        self.year = 0  # uint8

        self.previous_resource_testing_digest = 0  # uint32
        self.salted_resource_testing_digest = 0  # uint32

        self.previous_transaction_body_digest = 0  # uint32
        self.salted_transaction_body_digest = 0  # uint32

        self.previous_spectrum_digest = bytes([0] * 32)  # [32]byte
        self.previous_universe_digest = bytes([0] * 32)  # [32]byte
        self.previous_computer_digest = bytes([0] * 32)  # [32]byte

        self.salted_spectrum_digest = bytes([0] * 32)  # [32]byte
        self.salted_universe_digest = bytes([0] * 32)  # [32]byte
        self.salted_computer_digest = bytes([0] * 32)  # [32]byte

        self.tx_digest = bytes([0] * 32)  # [32]byte
        self.expected_next_tick_tx_digest = bytes([0] * 32)  # [32]byte

        self.signature = bytes([0] * 64)  # [64]byte

    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'computor_index': self.computor_index,
            'epoch': self.epoch,
            'tick': self.tick,
            'millisecond': self.millisecond,
            'second': self.second,
            'minute': self.minute,
            'hour': self.hour,
            'day': self.day,
            'month': self.month,
            'year': self.year,
            'previous_resource_testing_digest': self.previous_resource_testing_digest,
            'salted_resource_testing_digest': self.salted_resource_testing_digest,
            'previous_transaction_body_digest': self.previous_transaction_body_digest,
            'salted_transaction_body_digest': self.salted_transaction_body_digest,
            'previous_spectrum_digest': self.previous_spectrum_digest.hex(),
            'previous_universe_digest': self.previous_universe_digest.hex(),
            'previous_computer_digest': self.previous_computer_digest.hex(),
            'salted_spectrum_digest': self.salted_spectrum_digest.hex(),
            'salted_universe_digest': self.salted_universe_digest.hex(),
            'salted_computer_digest': self.salted_computer_digest.hex(),
            'tx_digest': self.tx_digest.hex(),
            'expected_next_tick_tx_digest': self.expected_next_tick_tx_digest.hex(),
            'signature': self.signature.hex()
        }

    def decode(self, conn: socket.socket):
        # Total size: 16 + 16 + (32 * 8) + 64 = 344 bytes
        data = must_recv(conn, 344)

        # Unpack fixed fields (16 bytes)
        (self.computor_index, self.epoch, self.tick, self.millisecond,
         self.second, self.minute, self.hour, self.day, self.month, 
         self.year) = struct.unpack('<HHIHBBBBBB', data[0:16])

        # Unpack digest fields (16 bytes)
        (self.previous_resource_testing_digest, self.salted_resource_testing_digest,
         self.previous_transaction_body_digest, self.salted_transaction_body_digest) = struct.unpack('<IIII', data[16:32])

        # Extract remaining byte arrays
        offset = 32
        self.previous_spectrum_digest = data[offset:offset+32]; offset += 32
        self.previous_universe_digest = data[offset:offset+32]; offset += 32
        self.previous_computer_digest = data[offset:offset+32]; offset += 32
        
        self.salted_spectrum_digest = data[offset:offset+32]; offset += 32
        self.salted_universe_digest = data[offset:offset+32]; offset += 32
        self.salted_computer_digest = data[offset:offset+32]; offset += 32
        
        self.tx_digest = data[offset:offset+32]; offset += 32
        self.expected_next_tick_tx_digest = data[offset:offset+32]; offset += 32
        
        self.signature = data[offset:offset+64]

class QuorumVotes(ResponseBody):
    MINIMUM_QUORUM_VOTES = 451

    def __init__(self):
        self.votes = []
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, QUORUM_TICK_RESPONSE)
            
            if header.type == END_RESPONSE:
                break

            vote = QuorumTickVote()
            vote.decode(conn)
            self.votes.append(vote)

def must_recv(conn: socket.socket, size: int):
    data = b''
    remaining = size
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ValueError(f"Connection closed while reading data: {remaining} < {size}")
        data += chunk
        remaining -= len(chunk)
    return data

class Computors(ResponseBody):
    NUMBER_OF_COMPUTORS = 676
    SIGNATURE_SIZE = 64

    def __init__(self):
        self.epoch = 0  # uint16
        self.pub_keys = []  # [NUMBER_OF_COMPUTORS][32]byte
        self.signature = bytes([0] * self.SIGNATURE_SIZE)  # [64]byte
    
    def __str__(self):
        return json.dumps(self.__dict__(), indent=2)
    
    def __dict__(self):
        return {
            'epoch': self.epoch,
            'pub_keys': [p.hex() for p in self.pub_keys],
            'signature': self.signature.hex()
        }
    
    def decode(self, conn):
        while True:
            header = RequestResponseHeader()
            header.decode(conn, BROADCAST_COMPUTORS)

            if header.type == END_RESPONSE:
                return

            # Read epoch (2 bytes)
            data = must_recv(conn, 2)
            self.epoch = struct.unpack('<H', data)[0]

            # Read public keys (676 * 32 = 21632 bytes)
            pub_keys_data = must_recv(conn, self.NUMBER_OF_COMPUTORS * 32)

            # Split into 32-byte chunks
            self.pub_keys = []
            for i in range(0, self.NUMBER_OF_COMPUTORS * 32, 32):
                pub_key = pub_keys_data[i:i+32]
                self.pub_keys.append(pub_key)

            # Read signature (64 bytes)
            signature_data = must_recv(conn, self.SIGNATURE_SIZE)
            self.signature = signature_data

            break


class SmartContractData(ResponseBody):
    def __init__(self):
        self.data = b''
    
    def decode(self, conn):
        header = RequestResponseHeader()
        header.decode(conn, CONTRACT_FUNCTION_RESPONSE)
                
        if header.type == END_RESPONSE:
            return
            
        # Calculate data size by subtracting header size from total size
        data_size = header.get_size() - 8  # header size is 8 bytes
        
        # Read data
        data = must_recv(conn, data_size)
            
        self.data = data


class Identity(ResponseBody):
    def __init__(self, identity_str: str):
        self.identity = identity_str

    def from_pub_key(self, pub_key: bytes, is_lower_case: bool = False) -> 'Identity':
        """Convert a 32-byte public key to an identity string"""
        letter = ord('a') if is_lower_case else ord('A')
        identity = bytearray(60)

        # Convert public key to identity string
        for i in range(4):
            pub_key_fragment = struct.unpack('<Q', pub_key[i*8:(i+1)*8])[0]
            for j in range(14):
                identity[i*14 + j] = (pub_key_fragment % 26) + letter
                pub_key_fragment //= 26

        # Calculate checksum using K12
        import hashlib # TODO: Replace with K12
        h = hashlib.sha256(pub_key) # Placeholder
        checksum = h.digest()[:3]
        
        checksum_int = checksum[0] | (checksum[1] << 8) | (checksum[2] << 16)
        checksum_int &= 0x3FFFF

        # Add checksum to identity
        for i in range(4):
            identity[56 + i] = (checksum_int % 26) + letter
            checksum_int //= 26

        return Identity(identity.decode())

    def to_pub_key(self, is_lower_case: bool = False) -> bytes:
        """Convert identity string to 32-byte public key"""
        letters = (ord('a'), ord('z')) if is_lower_case else (ord('A'), ord('Z'))
        pub_key = bytearray(32)

        # Validate identity format
        if not all(letters[0] <= ord(c) <= letters[1] for c in self.identity):
            raise ValueError("Invalid identity format")

        if len(self.identity) != 60:
            raise ValueError(f"Invalid identity length, expected 60, found {len(self.identity)}")

        # Convert identity to public key
        id_bytes = self.identity.encode()
        for i in range(4):
            val = 0
            for j in range(13, -1, -1):
                if not letters[0] <= id_bytes[i*14 + j] <= letters[1]:
                    raise ValueError("Invalid conversion")
                val = val * 26 + (id_bytes[i*14 + j] - letters[0])
            struct.pack_into('<Q', pub_key, i*8, val)

        return bytes(pub_key)

    def __str__(self):
        return self.identity if self.identity else ""


class TickRequest(RequestBody):
    def __init__(self, tick: int):
        self.tick = tick
    
    def encode(self) -> bytes:
        """Encode tick request to binary format"""
        return struct.pack('<I', self.tick)

class TickTransactionsRequest(RequestBody):
    def __init__(self, tick: int, transaction_flags: list):
        self.tick = tick
        self.transaction_flags = transaction_flags
    
    def encode(self) -> bytes:
        """Encode tick transactions request to binary format"""
        data = struct.pack('<I', self.tick)
        for flag in self.transaction_flags:
            data += struct.pack('<B', flag)
        return data

class QuorumRequest(RequestBody):
    def __init__(self, tick: int, vote_flags: list):
        self.tick = tick
        self.vote_flags = vote_flags
    
    def encode(self) -> bytes:
        """Encode quorum request to binary format"""
        data = struct.pack('<I', self.tick)
        for flag in self.vote_flags:
            data += struct.pack('<B', flag)
        return data

class AssetInformation:
    def __init__(self, identity: str, name: str):
        self.identity = identity
        self.name = name

class AssetHolderInformation:
    def __init__(self, identity: str, contract: int):
        self.identity = identity
        self.contract = contract

class RequestAssetsByFilter(RequestBody):
    def __init__(self, request_type: int, flags: int, ownership_managing_contract: int, 
                    possession_managing_contract: int, issuer: bytes, asset_name: bytes, 
                    owner: bytes, possessor: bytes):
        self.request_type = request_type
        self.flags = flags
        self.ownership_managing_contract = ownership_managing_contract
        self.possession_managing_contract = possession_managing_contract
        self.issuer = issuer
        self.asset_name = asset_name
        self.owner = owner
        self.possessor = possessor
    
    def encode(self) -> bytes:
        """Encode assets by filter request to binary format"""
        data = struct.pack('<H', self.request_type)  # uint16
        data += struct.pack('<H', self.flags)  # uint16
        data += struct.pack('<H', self.ownership_managing_contract)  # uint16
        data += struct.pack('<H', self.possession_managing_contract)  # uint16
        data += self.issuer  # [32]byte
        data += self.asset_name  # [8]byte
        data += self.owner  # [32]byte
        data += self.possessor  # [32]byte
        return data

class RequestAssetsByUniverseIndex(RequestBody):
    def __init__(self, request_type: int, universe_index: int):
        self.request_type = request_type
        self.universe_index = universe_index
    
    def encode(self) -> bytes:
        """Encode assets by universe index request to binary format"""
        data = struct.pack('<H', self.request_type)  # uint16
        data += struct.pack('<H', 0)  # flags (uint16)
        data += struct.pack('<I', self.universe_index)  # uint32
        data += bytes([0] * 104)  # padding [104]byte
        return data

class RequestContractFunction(RequestBody):
    def __init__(self, contract_index: int, input_type: int, input_size: int):
        self.contract_index = contract_index
        self.input_type = input_type
        self.input_size = input_size
    
    def encode(self) -> bytes:
        return struct.pack('<III', self.contract_index, self.input_type, self.input_size)
