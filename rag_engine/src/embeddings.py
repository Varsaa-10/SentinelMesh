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



class DenseMiniLMChunkedEmbedder(DenseMiniLMEmbedder):
    """
    Same model as dense-minilm, but long texts are not cut at 256 tokens.

    all-MiniLM-L6-v2 reads at most 256 word pieces. A KBRecord's text puts
    the description first and the detection signatures after it, and MITRE
    descriptions run 150-240 words, so with plain truncation the detection
    text of most answer records (and nearly all of every tactic summary) is
    never read. Here each text is split into overlapping 256-token windows
    (stride 32), each window is mean-pooled and normalised, and the window
    vectors are averaged and normalised again.
    """
    name = "dense-minilm-chunked"
    window_batch = 64

    def embed(self, texts: List[str]) -> np.ndarray:
        import torch
        import torch.nn.functional as F
        if not texts:
            return np.empty((0, 384), dtype=np.float32)
        out = []
        for text in texts:
            enc = self.tokenizer(text or "", truncation=True, max_length=256, stride=32,
                                 return_overflowing_tokens=True, padding=True, return_tensors="pt")
            enc.pop("overflow_to_sample_mapping", None)
            vecs = []
            n = enc["input_ids"].shape[0]
            for s in range(0, n, self.window_batch):
                part = {k: v[s:s + self.window_batch].to(self.device) for k, v in enc.items()}
                with torch.no_grad():
                    hidden = self.model(**part).last_hidden_state
                mask = part["attention_mask"].unsqueeze(-1).float()
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                vecs.append(F.normalize(pooled, p=2, dim=1))
            doc = torch.cat(vecs).mean(dim=0, keepdim=True)
            out.append(F.normalize(doc, p=2, dim=1))
        return torch.cat(out).cpu().numpy().astype(np.float32)


EMBEDDERS["dense-minilm-chunked"] = DenseMiniLMChunkedEmbedder


# ---------------------------------------------------------------------------
# ONNX build of all-MiniLM-L6-v2 (no PyTorch needed). Point SENTINELMESH_MINILM_ONNX
# at a folder holding tokenizer.json and onnx/model.onnx (the Xenova export of
# sentence-transformers/all-MiniLM-L6-v2). Mean pooling + L2 normalisation, as in
# sentence-transformers. Embeddings are cached per text, so knowledge-base
# variants that share most records reuse them.
# ---------------------------------------------------------------------------
import os as _os

_ONNX_CACHE: dict = {}
_ONNX_SESSION = {}


def _onnx_minilm(model_dir: str):
    if model_dir not in _ONNX_SESSION:
        import onnxruntime as ort
        from tokenizers import Tokenizer
        tok = Tokenizer.from_file(_os.path.join(model_dir, "tokenizer.json"))
        tok.no_padding()
        sess = ort.InferenceSession(_os.path.join(model_dir, "onnx", "model.onnx"),
                                    providers=["CPUExecutionProvider"])
        _ONNX_SESSION[model_dir] = (tok, sess)
    return _ONNX_SESSION[model_dir]


class DenseOnnxMiniLMEmbedder(BaseEmbedder):
    """all-MiniLM-L6-v2 through ONNX Runtime. chunked=False cuts every text at 256
    word pieces (what sentence-transformers does by default); chunked=True reads the
    whole text in overlapping 256-token windows (stride 32) and averages the window
    vectors."""
    name = "dense-minilm-onnx"
    chunked = False
    max_len = 256
    stride = 32
    batch = 64

    def __init__(self, model_dir: str = None):
        self.model_dir = model_dir or _os.environ.get("SENTINELMESH_MINILM_ONNX", "models/all-MiniLM-L6-v2")
        self.tok, self.sess = _onnx_minilm(self.model_dir)
        self._inputs = {i.name for i in self.sess.get_inputs()}

    def fit(self, corpus: List[str]) -> None:
        pass

    def _windows(self, text: str):
        self.tok.enable_truncation(max_length=self.max_len, stride=self.stride if self.chunked else 0)
        enc = self.tok.encode(text or "")
        wins = [enc] + (list(enc.overflowing) if self.chunked else [])
        return [(w.ids, w.attention_mask, w.type_ids) for w in wins]

    def _run(self, wins):
        out = []
        for s in range(0, len(wins), self.batch):
            part = wins[s:s + self.batch]
            L = max(len(w[0]) for w in part)
            ids = np.zeros((len(part), L), dtype=np.int64)
            mask = np.zeros((len(part), L), dtype=np.int64)
            tt = np.zeros((len(part), L), dtype=np.int64)
            for i, (a, m, t) in enumerate(part):
                ids[i, :len(a)] = a; mask[i, :len(m)] = m; tt[i, :len(t)] = t
            feed = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self._inputs:
                feed["token_type_ids"] = tt
            hidden = self.sess.run(None, feed)[0]
            m = mask[..., None].astype(np.float32)
            pooled = (hidden * m).sum(1) / np.clip(m.sum(1), 1e-9, None)
            pooled /= np.clip(np.linalg.norm(pooled, axis=1, keepdims=True), 1e-12, None)
            out.append(pooled)
        return np.concatenate(out)

    def embed(self, texts: List[str]) -> np.ndarray:
        res = []
        for t in texts:
            key = (self.chunked, t)
            if key not in _ONNX_CACHE:
                v = self._run(self._windows(t)).mean(0)
                _ONNX_CACHE[key] = (v / max(np.linalg.norm(v), 1e-12)).astype(np.float32)
            res.append(_ONNX_CACHE[key])
        return np.vstack(res) if res else np.empty((0, 384), dtype=np.float32)


class DenseOnnxMiniLMChunkedEmbedder(DenseOnnxMiniLMEmbedder):
    name = "dense-minilm-onnx-chunked"
    chunked = True


class HybridTfidfDenseEmbedder(BaseEmbedder):
    """Equal-weight hybrid: the cosine of the joined vector is 0.5 * TF-IDF cosine +
    0.5 * dense cosine, because both halves are unit-length and scaled by sqrt(0.5)."""
    name = "hybrid-tfidf-dense"
    weight_sparse = 0.5

    def __init__(self):
        self.sparse = WordTfidfEmbedder()
        self.dense = DenseOnnxMiniLMChunkedEmbedder()

    def fit(self, corpus: List[str]) -> None:
        self.sparse.fit(corpus)

    def embed(self, texts: List[str]) -> np.ndarray:
        a = self.sparse.embed(texts)
        a = a / np.clip(np.linalg.norm(a, axis=1, keepdims=True), 1e-12, None)
        b = self.dense.embed(texts)
        return np.hstack([a * np.sqrt(self.weight_sparse), b * np.sqrt(1 - self.weight_sparse)])


EMBEDDERS["dense-minilm-onnx"] = DenseOnnxMiniLMEmbedder
EMBEDDERS["dense-minilm-onnx-chunked"] = DenseOnnxMiniLMChunkedEmbedder
EMBEDDERS["hybrid-tfidf-dense"] = HybridTfidfDenseEmbedder
