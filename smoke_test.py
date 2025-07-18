from qubicly.qubic import QubicClient

from dotenv import load_dotenv
import os

if __name__ == "__main__":
    load_dotenv()
    
    tick = 29669935
    id = os.getenv('QUBIC_ID', 'AYVZGZNMKUSLZCHXVSUXNNYNINNAZARHNFTJSEYJKFETIRFMWKAGVVWCBCNJ')
    ip = os.getenv('QUBIC_NODE_IP', '178.39.19.107')
    port = int(os.getenv('QUBIC_NODE_PORT', '21841'))

    client = QubicClient(ip, port)
    print("Tick info: ", client.get_tick_info())
    print("System info: ", client.get_system_info())
    # print(client.get_tx_status(29436874))
    print("Tick data: ", client.get_tick_data(tick))
    print("Tick transactions: ", client.get_tick_transactions(tick))
    # print(client.get_quorum_votes(29436874))
    print("Computors: ", client.get_computors())
    print("Identity: ", client.get_identity(id))

    print("Issued assets: ", client.get_issued_assets(id))
    print("Possessed assets: ", client.get_possessed_assets(id))
    print("Owned assets: ", client.get_owned_assets(id))

