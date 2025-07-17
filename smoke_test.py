from qubicly.qubic import QubicClient


if __name__ == "__main__":
    tick = 29669935
    id = "AYVZGZNMKUSLZCHXVSUXNNYNINNAZARHNFTJSEYJKFETIRFMWKAGVVWCBCNJ"

    client = QubicClient("45.152.160.28", 21841)
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

