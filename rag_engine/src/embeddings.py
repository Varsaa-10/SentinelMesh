"""
Embedding backends for the RAG engine.

Two embedding models are provided so Day-4's required embedding-model
comparison has something real to compare:

  - "tfidf-word"  : word-level TF-IDF (1-2 grams)   -> WordTfidfEmbedder
  - "tfidf-char"  : char-level TF-IDF (3-5 grams)    -> CharTfidfEmbedder

This environment has no network access to model-hosting domains
(huggingface.co etc. are not in the allowed egress list), so these two
classic, fully-offline vectorizers stand in for "2 embedding models" per
the Day-4 task. Both implement the same tiny interface
(`fit(corpus)` / `embed(text)` / `similarity(a, b)`), so swapping in a
real embedding API (OpenAI, sentence-transformers, Voyage, etc.) later
is a drop-in replacement -- just implement the same interface.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class BaseEmbedder:
    name: str = "base"

    def fit(self, corpus: List[str]) -> None:
        raise NotImplementedError

    def embed(self, texts: List[str]) -> np.ndarray:
        raise NotImplementedError

    def similarity_matrix(self, query_vecs: np.ndarray, doc_vecs: np.ndarray) -> np.ndarray:
        return cosine_similarity(query_vecs, doc_vecs)


class WordTfidfEmbedder(BaseEmbedder):
    """Word-level TF-IDF, 1-2 grams. Fast, interpretable, good baseline."""
    name = "tfidf-word"

    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words="english")
        self._fitted = False

    def fit(self, corpus: List[str]) -> None:
        self.vectorizer.fit(corpus)
        self._fitted = True

    def embed(self, texts: List[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError(f"{self.name}: call fit() before embed()")
        return self.vectorizer.transform(texts).toarray()


class CharTfidfEmbedder(BaseEmbedder):
    """Char-level TF-IDF, 3-5 grams. More robust to typos/short technique names."""
    name = "tfidf-char"

    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)
        self._fitted = False

    def fit(self, corpus: List[str]) -> None:
        self.vectorizer.fit(corpus)
        self._fitted = True

    def embed(self, texts: List[str]) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError(f"{self.name}: call fit() before embed()")
        return self.vectorizer.transform(texts).toarray()


EMBEDDERS = {
    "tfidf-word": WordTfidfEmbedder,
    "tfidf-char": CharTfidfEmbedder,
}
