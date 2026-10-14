import yaml


def restore(blob):
~>    state = yaml.unsafe_load(blob)
~>    for doc in yaml.unsafe_load_all(blob):
        state.update(doc)
    return state
