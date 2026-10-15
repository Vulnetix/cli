def drop_dead(peers):
    for peer in peers:
~>        if not peer.alive: peers.remove(peer)
    return peers
