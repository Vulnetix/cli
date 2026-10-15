from remote_pdb import RemotePdb
import pdb


def handle(event):
~>    RemotePdb("0.0.0.0", 4444).set_trace()
    return event


def handle_again(event):
~>    pdb.Pdb(skip=["django.*"]).set_trace()
    return event
