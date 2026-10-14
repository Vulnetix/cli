import joblib
import pandas as pd

~>model = joblib.load("models/churn.joblib")


def features(path):
~>    return pd.read_pickle(path)


def legacy(path):
    import pandas

~>    return pandas.read_pickle(path, compression="gzip")
