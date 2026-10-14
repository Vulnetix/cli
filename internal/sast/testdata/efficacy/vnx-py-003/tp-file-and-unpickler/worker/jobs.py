import io
import pickle


def restore(upload_path, blob):
    with open(upload_path, "rb") as fh:
~>        state = pickle.load(fh)
~>    job = pickle.Unpickler(io.BytesIO(blob)).load()
    return state, job
