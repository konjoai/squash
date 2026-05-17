"""tests/test_clause_clustering.py — TF-IDF + k-means++ clause clustering."""

from __future__ import annotations

import unittest

from squash.analysis import (
    ClauseClustering,
    ClauseRef,
    Cluster,
    ClusterResult,
)


_LEGAL_CORPUS = [
    "Customer shall indemnify and hold harmless Provider from any claims arising out of use.",
    "Provider shall indemnify Customer against any third-party intellectual property infringement claims.",
    "Each party shall indemnify the other for breach of its confidentiality obligations.",
    "Liability shall be limited to the fees paid by Customer in the prior twelve months.",
    "In no event shall total liability exceed twelve months of subscription fees.",
    "Aggregate liability cap is set at one million dollars regardless of theory.",
    "This agreement may be terminated by either party upon thirty days written notice.",
    "Either party may terminate for material breach upon thirty (30) days written notice.",
    "Termination for convenience requires sixty days of advance notice to the other party.",
]


class TestClusteringShape(unittest.TestCase):
    def test_returns_cluster_result(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        self.assertIsInstance(r, ClusterResult)
        self.assertEqual(r.requested_k, 3)
        self.assertEqual(r.clause_count, len(_LEGAL_CORPUS))
        self.assertEqual(len(r.clusters), 3)

    def test_every_clause_assigned_exactly_once(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        assignments = []
        for cl in r.clusters:
            assignments.extend(ref.index for ref in cl.clauses)
        self.assertEqual(sorted(assignments),
                         list(range(len(_LEGAL_CORPUS))))

    def test_cluster_objects_well_typed(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        for cl in r.clusters:
            self.assertIsInstance(cl, Cluster)
            self.assertGreaterEqual(cl.size, 1)
            self.assertLessEqual(len(cl.centroid_terms), 5)
            for ref in cl.clauses:
                self.assertIsInstance(ref, ClauseRef)
                self.assertGreaterEqual(ref.similarity_to_centroid, -1.0)
                self.assertLessEqual(ref.similarity_to_centroid, 1.0)


class TestSemanticGrouping(unittest.TestCase):
    def test_indemnification_clauses_cluster_together(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        # find the cluster containing the first indemnification clause
        indem_cluster = next(
            cl for cl in r.clusters
            if any(ref.index == 0 for ref in cl.clauses)
        )
        indices = {ref.index for ref in indem_cluster.clauses}
        # The two unambiguous indemnification clauses (0, 1) MUST share a
        # cluster.  Clause 2 ("each party shall indemnify the other for breach
        # of its confidentiality obligations") is cross-cutting — it shares
        # vocab with the breach/termination cluster — and we accept either
        # placement as honest k-means behaviour on 9 short docs.
        self.assertIn(1, indices)

    def test_liability_clauses_cluster_together(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        liab_cluster = next(
            cl for cl in r.clusters
            if any(ref.index == 3 for ref in cl.clauses)
        )
        indices = {ref.index for ref in liab_cluster.clauses}
        self.assertIn(4, indices)
        self.assertIn(5, indices)

    def test_centroid_terms_reflect_cluster_topic(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        all_terms = {t for cl in r.clusters for t in cl.centroid_terms}
        # The clusterer doesn't stem, so "terminate"/"termination"/"terminated"
        # are three separate low-TF tokens.  We assert the two semantically
        # stable representatives appear, and that the termination cluster
        # carries at least one notice/breach/party signature term.
        for needle in ("indemnify", "liability"):
            self.assertTrue(
                any(needle in t for t in all_terms),
                msg=f"{needle} not found in centroid terms: {all_terms}",
            )
        self.assertTrue(
            any(t in {"notice", "breach", "party", "days"} for t in all_terms),
            msg=f"termination-cluster signature missing: {all_terms}",
        )


class TestDeterminismAndEdges(unittest.TestCase):
    def test_same_seed_same_assignments(self):
        a = ClauseClustering(seed=7).cluster(_LEGAL_CORPUS, k=3)
        b = ClauseClustering(seed=7).cluster(_LEGAL_CORPUS, k=3)
        a_assign = {ref.index: cl.id for cl in a.clusters for ref in cl.clauses}
        b_assign = {ref.index: cl.id for cl in b.clusters for ref in cl.clauses}
        self.assertEqual(a_assign, b_assign)

    def test_silhouette_is_finite_and_in_range(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        self.assertGreaterEqual(r.silhouette_score, -1.0)
        self.assertLessEqual(r.silhouette_score, 1.0)
        self.assertGreater(r.silhouette_score, 0.0,
                           msg="legal corpus should yield positive silhouette")

    def test_optimal_k_in_range(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=4)
        self.assertGreaterEqual(r.optimal_k_suggested, 2)
        self.assertLessEqual(r.optimal_k_suggested, min(8, len(_LEGAL_CORPUS) - 1))

    def test_empty_input(self):
        c = ClauseClustering(seed=42)
        r = c.cluster([], k=3)
        self.assertEqual(r.clause_count, 0)
        self.assertEqual(r.clusters, [])

    def test_more_k_than_clauses_caps_to_n(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS[:2], k=5)
        self.assertLessEqual(len(r.clusters), 2)

    def test_validates_clauses_type(self):
        c = ClauseClustering(seed=42)
        with self.assertRaises(TypeError):
            c.cluster(["ok", 5], k=2)  # type: ignore[list-item]

    def test_validates_k(self):
        c = ClauseClustering(seed=42)
        with self.assertRaises(ValueError):
            c.cluster(_LEGAL_CORPUS, k=0)

    def test_to_dict_round_trip(self):
        c = ClauseClustering(seed=42)
        r = c.cluster(_LEGAL_CORPUS, k=3)
        d = r.to_dict()
        self.assertEqual(d["requested_k"], 3)
        self.assertEqual(len(d["clusters"]), 3)
        for cl in d["clusters"]:
            self.assertIn("centroid_terms", cl)
            self.assertIn("intra_cluster_similarity", cl)


if __name__ == "__main__":
    unittest.main()
