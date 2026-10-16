import joblib
import pandas as pd


def restore(cache_path):
~>    clf = joblib.load("classifier.pkl")
~>    df = pd.read_pickle(cache_path)
    return clf, df
