import jsonpickle
import pickle


def import_state(request):
~>    obj = pickle.loads(
        request.get_data()
    )
~>    cfg = jsonpickle.decode(request.form["cfg"])
    return obj, cfg
