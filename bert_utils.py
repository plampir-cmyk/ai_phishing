from sklearn.base import BaseEstimator, TransformerMixin
from sentence_transformers import SentenceTransformer

class BertTransformer(BaseEstimator, TransformerMixin):
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        self.model_name = model_name
        self.model = None

    def fit(self, X, y=None):
        if self.model is None:
            self.model = SentenceTransformer(self.model_name)
        return self

    def transform(self, X):
        if self.model is None:
            self.model = SentenceTransformer(self.model_name)
        texts = X.tolist() if hasattr(X, 'tolist') else list(X)
        return self.model.encode(texts, show_progress_bar=False)
