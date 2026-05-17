"""squash/analysis/clustering.py — TF-IDF + k-means++ clause clustering.

Group similar contract clauses (e.g. all *indemnification* clauses, all
*limitation of liability* clauses) using cosine similarity over TF-IDF
vectors and k-means++ initialisation. Pure Python — no numpy, no sklearn,
no torch — so the package keeps its zero-runtime-dependency posture.

Public surface (re-exported from ``squash.analysis``)
-----------------------------------------------------
:class:`ClauseRef` · :class:`Cluster` · :class:`ClusterResult` ·
:class:`ClauseClustering`

The algorithm
-------------
1. Tokenise each clause: lowercase, strip punctuation, drop stopwords,
   keep tokens of length >= 2.
2. Build a sparse term-document matrix (``dict[term -> count]`` per doc).
3. Compute TF (raw count) and IDF (``log((N + 1) / (df + 1)) + 1``).
4. L2-normalise each TF-IDF vector so cosine similarity reduces to a
   plain dot product.
5. Initialise k centroids with k-means++ (D² sampling).
6. Iterate Lloyd's algorithm until cluster assignments stabilise or
   ``max_iter`` is hit. Distance metric is ``1 - cosine_similarity``.
7. Compute silhouette score (sampled) for the chosen *k*, plus a cheap
   elbow estimate of the optimal *k* by sweeping 2..min(8, n-1).

Determinism
-----------
A ``seed`` argument seeds the local PRNG so the same input set produces
the same cluster assignment on every run.
"""

from __future__ import annotations

import math
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ClauseClustering",
    "ClauseRef",
    "Cluster",
    "ClusterResult",
]


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class ClauseRef:
    index: int
    text: str
    similarity_to_centroid: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "text": self.text,
            "similarity_to_centroid": round(self.similarity_to_centroid, 4),
        }


@dataclass
class Cluster:
    id: int
    size: int
    centroid_terms: list[str]
    clauses: list[ClauseRef] = field(default_factory=list)
    intra_cluster_similarity: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "size": self.size,
            "centroid_terms": list(self.centroid_terms),
            "clauses": [c.to_dict() for c in self.clauses],
            "intra_cluster_similarity": round(self.intra_cluster_similarity, 4),
        }


@dataclass
class ClusterResult:
    clusters: list[Cluster] = field(default_factory=list)
    silhouette_score: float = 0.0
    optimal_k_suggested: int = 0
    requested_k: int = 0
    clause_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "clusters": [c.to_dict() for c in self.clusters],
            "silhouette_score": round(self.silhouette_score, 4),
            "optimal_k_suggested": self.optimal_k_suggested,
            "requested_k": self.requested_k,
            "clause_count": self.clause_count,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Stopwords (compact, hand-curated for legal text)
# ──────────────────────────────────────────────────────────────────────────────

_STOPWORDS: frozenset[str] = frozenset({
    "the", "a", "an", "and", "or", "but", "if", "in", "on", "at", "to", "of",
    "for", "with", "by", "from", "as", "is", "was", "are", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "must", "shall", "this", "that", "these", "those",
    "it", "its", "such", "any", "all", "each", "every", "no", "not", "nor",
    "so", "than", "then", "into", "out", "up", "down", "over", "under", "above",
    "below", "between", "among", "through", "during", "before", "after", "within",
    "without", "against", "about", "across", "upon", "you", "your", "we", "our",
    "us", "they", "them", "their", "he", "she", "his", "her", "him", "i", "me",
    "my", "mine", "ourselves", "yourselves", "themselves", "who", "whom", "which",
    "what", "where", "when", "why", "how",
})

_TOKEN_RE = re.compile(r"[a-z]+(?:[-'][a-z]+)*")


def _tokenize(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for tok in _TOKEN_RE.findall(text.lower()):
        if len(tok) >= 2 and tok not in _STOPWORDS:
            out.append(tok)
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Vector ops (sparse dict[term -> weight])
# ──────────────────────────────────────────────────────────────────────────────


def _norm(vec: dict[str, float]) -> float:
    return math.sqrt(sum(v * v for v in vec.values()))


def _l2_normalize(vec: dict[str, float]) -> dict[str, float]:
    n = _norm(vec)
    if n <= 0.0:
        return {}
    return {k: v / n for k, v in vec.items()}


def _dot(a: dict[str, float], b: dict[str, float]) -> float:
    # Iterate the shorter vector for speed.
    if len(a) > len(b):
        a, b = b, a
    s = 0.0
    for k, v in a.items():
        w = b.get(k)
        if w is not None:
            s += v * w
    return s


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    # Vectors are pre-normalised in ClauseClustering, so dot == cosine.
    return _dot(a, b)


def _add_in_place(target: dict[str, float], src: dict[str, float]) -> None:
    for k, v in src.items():
        target[k] = target.get(k, 0.0) + v


def _scale_in_place(target: dict[str, float], factor: float) -> None:
    if factor == 1.0:
        return
    for k in list(target.keys()):
        target[k] *= factor


# ──────────────────────────────────────────────────────────────────────────────
# Clustering
# ──────────────────────────────────────────────────────────────────────────────


class ClauseClustering:
    """Cluster contract clauses by TF-IDF cosine similarity."""

    def __init__(
        self,
        *,
        seed: int = 42,
        max_iter: int = 80,
        max_k_for_optimal_sweep: int = 8,
    ) -> None:
        self._seed = int(seed)
        self._max_iter = int(max_iter)
        self._max_k_sweep = int(max_k_for_optimal_sweep)

    # ── public ─────────────────────────────────────────────────────────────

    def cluster(self, clauses: list[str], k: int = 5) -> ClusterResult:
        if not isinstance(clauses, list) or any(not isinstance(c, str) for c in clauses):
            raise TypeError("clauses must be list[str]")
        if k < 1:
            raise ValueError("k must be >= 1")

        clean = [c.strip() for c in clauses if c and c.strip()]
        n = len(clean)
        result = ClusterResult(requested_k=k, clause_count=n)
        if n == 0:
            return result

        # Edge case — fewer clauses than requested clusters: collapse.
        effective_k = min(k, n)

        # 1. tokenise + build vocabulary + doc-frequency
        tokens_per_doc = [_tokenize(c) for c in clean]
        df: Counter[str] = Counter()
        for toks in tokens_per_doc:
            for term in set(toks):
                df[term] += 1
        N = n

        # 2. TF-IDF (L2-normalised)
        vectors: list[dict[str, float]] = []
        for toks in tokens_per_doc:
            tf = Counter(toks)
            vec: dict[str, float] = {}
            for term, count in tf.items():
                idf = math.log((N + 1) / (df[term] + 1)) + 1.0
                vec[term] = float(count) * idf
            vectors.append(_l2_normalize(vec))

        # 3. assignment + centroids
        rng = random.Random(self._seed)
        assignments, centroids = self._fit(vectors, effective_k, rng)

        # 4. build per-cluster outputs
        clusters_out: list[Cluster] = []
        for cid in range(effective_k):
            members = [i for i, a in enumerate(assignments) if a == cid]
            cluster_clauses = []
            sims = []
            for i in members:
                sim = _cosine(vectors[i], centroids[cid])
                cluster_clauses.append(ClauseRef(
                    index=i, text=clean[i],
                    similarity_to_centroid=sim,
                ))
                sims.append(sim)
            cluster_clauses.sort(key=lambda c: -c.similarity_to_centroid)
            avg = sum(sims) / len(sims) if sims else 0.0
            clusters_out.append(Cluster(
                id=cid,
                size=len(members),
                centroid_terms=self._top_terms(centroids[cid], 5),
                clauses=cluster_clauses,
                intra_cluster_similarity=avg,
            ))

        # 5. silhouette + optimal-k suggestion
        result.clusters = clusters_out
        result.silhouette_score = self._silhouette(vectors, assignments, effective_k)
        result.optimal_k_suggested = self._suggest_optimal_k(vectors, rng)
        return result

    # ── k-means++ ──────────────────────────────────────────────────────────

    def _fit(
        self,
        vectors: list[dict[str, float]],
        k: int,
        rng: random.Random,
    ) -> tuple[list[int], list[dict[str, float]]]:
        n = len(vectors)
        if k >= n:
            # one cluster per doc (or padded with copies)
            return list(range(n))[:n], [dict(vectors[i]) for i in range(n)][:n]

        centroids = self._kmeans_pp_init(vectors, k, rng)
        assignments = [0] * n
        prev_assignments: list[int] | None = None

        for _ in range(self._max_iter):
            # E-step
            for i, v in enumerate(vectors):
                assignments[i] = self._closest(v, centroids)
            if assignments == prev_assignments:
                break
            prev_assignments = list(assignments)

            # M-step
            new_centroids: list[dict[str, float]] = [dict() for _ in range(k)]
            counts = [0] * k
            for i, a in enumerate(assignments):
                _add_in_place(new_centroids[a], vectors[i])
                counts[a] += 1
            for c in range(k):
                if counts[c] > 0:
                    _scale_in_place(new_centroids[c], 1.0 / counts[c])
                    new_centroids[c] = _l2_normalize(new_centroids[c])
                else:
                    # empty cluster — reseed to the farthest point
                    far = self._farthest_from_any(vectors, centroids, rng)
                    new_centroids[c] = dict(vectors[far])
            centroids = new_centroids

        return assignments, centroids

    def _kmeans_pp_init(
        self,
        vectors: list[dict[str, float]],
        k: int,
        rng: random.Random,
    ) -> list[dict[str, float]]:
        n = len(vectors)
        first = rng.randrange(n)
        centroids: list[dict[str, float]] = [dict(vectors[first])]
        for _ in range(1, k):
            d2 = [self._min_dist_sq(v, centroids) for v in vectors]
            total = sum(d2)
            if total <= 0.0:
                idx = rng.randrange(n)
            else:
                target = rng.random() * total
                cum = 0.0
                idx = n - 1
                for i, w in enumerate(d2):
                    cum += w
                    if cum >= target:
                        idx = i
                        break
            centroids.append(dict(vectors[idx]))
        return centroids

    @staticmethod
    def _closest(v: dict[str, float], centroids: list[dict[str, float]]) -> int:
        best = 0
        best_sim = -2.0
        for i, c in enumerate(centroids):
            s = _cosine(v, c)
            if s > best_sim:
                best_sim = s
                best = i
        return best

    @staticmethod
    def _min_dist_sq(
        v: dict[str, float],
        centroids: list[dict[str, float]],
    ) -> float:
        """Cosine distance squared from v to its nearest centroid."""
        best_sim = -2.0
        for c in centroids:
            s = _cosine(v, c)
            if s > best_sim:
                best_sim = s
        # distance ∈ [0, 2] for unit vectors; clamp negatives just in case
        d = max(0.0, 1.0 - best_sim)
        return d * d

    @staticmethod
    def _farthest_from_any(
        vectors: list[dict[str, float]],
        centroids: list[dict[str, float]],
        rng: random.Random,
    ) -> int:
        best_i, best_d = 0, -1.0
        for i, v in enumerate(vectors):
            best_sim = -2.0
            for c in centroids:
                s = _cosine(v, c)
                if s > best_sim:
                    best_sim = s
            d = 1.0 - best_sim
            if d > best_d:
                best_d = d
                best_i = i
        return best_i

    # ── auxiliary ──────────────────────────────────────────────────────────

    @staticmethod
    def _top_terms(centroid: dict[str, float], n: int) -> list[str]:
        return [t for t, _ in sorted(
            centroid.items(), key=lambda kv: -kv[1],
        )[:n]]

    @staticmethod
    def _silhouette(
        vectors: list[dict[str, float]],
        assignments: list[int],
        k: int,
        sample_cap: int = 200,
    ) -> float:
        n = len(vectors)
        if n < 2 or k < 2:
            return 0.0

        indices = list(range(n))
        if n > sample_cap:
            rng_local = random.Random(0)
            indices = rng_local.sample(indices, sample_cap)

        scores: list[float] = []
        by_cluster: dict[int, list[int]] = {}
        for i, a in enumerate(assignments):
            by_cluster.setdefault(a, []).append(i)

        for i in indices:
            own = assignments[i]
            same = by_cluster.get(own, [])
            if len(same) < 2:
                scores.append(0.0)
                continue
            # a(i): mean distance to others in same cluster
            a_sum = 0.0
            for j in same:
                if j == i:
                    continue
                a_sum += 1.0 - _cosine(vectors[i], vectors[j])
            a_i = a_sum / (len(same) - 1)
            # b(i): mean distance to nearest other cluster
            b_i = float("inf")
            for other_cid, members in by_cluster.items():
                if other_cid == own or not members:
                    continue
                d_sum = 0.0
                for j in members:
                    d_sum += 1.0 - _cosine(vectors[i], vectors[j])
                d_avg = d_sum / len(members)
                if d_avg < b_i:
                    b_i = d_avg
            denom = max(a_i, b_i) if max(a_i, b_i) > 0 else 1.0
            scores.append((b_i - a_i) / denom)
        return sum(scores) / len(scores) if scores else 0.0

    def _suggest_optimal_k(
        self,
        vectors: list[dict[str, float]],
        rng: random.Random,
    ) -> int:
        """Sweep small k values and pick the one with best silhouette."""
        n = len(vectors)
        if n <= 2:
            return min(n, 1)
        upper = min(self._max_k_sweep, n - 1)
        best_k = 2
        best_score = -2.0
        for trial_k in range(2, upper + 1):
            # use a fresh PRNG seeded with the trial so the sweep is deterministic
            local_rng = random.Random(self._seed * 1000 + trial_k)
            assigns, _ = self._fit(vectors, trial_k, local_rng)
            score = self._silhouette(vectors, assigns, trial_k)
            if score > best_score:
                best_score = score
                best_k = trial_k
        return best_k
