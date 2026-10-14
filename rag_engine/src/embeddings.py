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


class DenseMiniLMEmbedder(BaseEmbedder):
    """
    Offline Dense Sentence Embedder using all-MiniLM-L6-v2 (384-dimensional).
    Mean-pooled token representations with L2 normalization.
    """
    name = "dense-minilm"
    model_name = "sentence-transformers/all-MiniLM-L6-v2"
    commit_hash = "c9745ed1d9f207416be6d2e6f8de32d1f16199bf"
    sha256_checksum = "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"

    def __init__(self, model_name_or_path: str = "sentence-transformers/all-MiniLM-L6-v2"):
        import torch
        from transformers import AutoTokenizer, AutoModel
        self.device = torch.device("cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name_or_path, local_files_only=True)
        self.model = AutoModel.from_pretrained(model_name_or_path, local_files_only=True).to(self.device)
        self.model.eval()

    def fit(self, corpus: List[str]) -> None:
        # Pretrained dense models do not require corpus fitting
        pass

    def embed(self, texts: List[str]) -> np.ndarray:
        import torch
        import torch.nn.functional as F
        if not texts:
            return np.empty((0, 384), dtype=np.float32)
        
        # Batch tokenization
        encoded = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=256,
            return_tensors="pt"
        ).to(self.device)

        with torch.no_grad():
            output = self.model(**encoded)
            attention_mask = encoded["attention_mask"].unsqueeze(-1).expand(output.last_hidden_state.size()).float()
            sum_embeddings = torch.sum(output.last_hidden_state * attention_mask, dim=1)
            sum_mask = torch.clamp(attention_mask.sum(dim=1), min=1e-9)
            mean_pooled = sum_embeddings / sum_mask
            normalized = F.normalize(mean_pooled, p=2, dim=1)
            
        return normalized.cpu().numpy().astype(np.float32)


EMBEDDERS = {
    "tfidf-word": WordTfidfEmbedder,
    "tfidf-char": CharTfidfEmbedder,
    "dense-minilm": DenseMiniLMEmbedder,
}

