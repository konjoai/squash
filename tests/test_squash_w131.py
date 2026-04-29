"""tests/test_squash_w131.py — Wave 131: HuggingFace Datasets provenance.

Tests DatasetProvenance, completeness scoring, bias detection, and
ArtifactExtractor.from_huggingface_dataset() / from_huggingface_dataset_list()
via mocked huggingface_hub.HfApi — zero network calls, no credentials.

Coverage:
  - _has_bias_content(): keyword detection
  - _extract_citation(): BibTeX extraction from README
  - _parse_hf_tags(): namespace:value splitting
  - _build_dataset_provenance(): license, language, tasks, size, dates, tags
  - DatasetProvenance.completeness_score(): weighted scoring (0–100)
  - DatasetProvenance.completeness_gaps(): missing field labels
  - DatasetProvenance.annex_iv_section_2a(): full §2(a) block structure
  - DatasetProvenance.to_dict(): alias for annex_iv_section_2a
  - from_huggingface_dataset(): delegates to mocked HfApi + DatasetCard
  - from_huggingface_dataset(): card load failure handled gracefully
  - from_huggingface_dataset(): ImportError when huggingface_hub absent
  - from_huggingface_dataset_list(): all succeed
  - from_huggingface_dataset_list(): partial failure gives fallback record
  - ArtifactExtractionResult.datasets field + is_empty() + to_annex_iv_dict()
  - section_2a present in combined annex_iv_dict output
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import huggingface_hub  # ensure real module is in sys.modules before any test stubs it

from squash.artifact_extractor import (
    ArtifactExtractor,
    ArtifactExtractionResult,
    DatasetProvenance,
    _build_dataset_provenance,
    _extract_citation,
    _has_bias_content,
    _parse_hf_tags,
)


# ---------------------------------------------------------------------------
# Fixtures — mock HuggingFace Hub objects
# ---------------------------------------------------------------------------

def _make_card_data(
    language: list[str] | None = None,
    license: str | None = None,
    task_categories: list[str] | None = None,
    size_categories: list[str] | None = None,
    source_datasets: list[str] | None = None,
    pretty_name: str | None = None,
) -> MagicMock:
    cd = MagicMock()
    cd.language = language or ["en"]
    cd.license = license or "apache-2.0"
    cd.task_categories = task_categories or ["question-answering"]
    cd.size_categories = size_categories or ["10K<n<100K"]
    cd.source_datasets = source_datasets or ["original"]
    cd.pretty_name = pretty_name or "SQuAD"
    return cd


def _make_dataset_info(
    dataset_id: str = "squad",
    tags: list[str] | None = None,
    card_data=None,
    created_at=None,
    last_modified=None,
    downloads: int = 500_000,
) -> MagicMock:
    info = MagicMock()
    info.id = dataset_id
    info.tags = tags or [
        "language:en",
        "license:cc-by-4.0",
        "size_categories:10K<n<100K",
        "task_categories:question-answering",
    ]
    info.card_data = card_data if card_data is not None else _make_card_data()
    info.created_at = created_at or datetime(2021, 6, 1, tzinfo=timezone.utc)
    info.last_modified = last_modified or datetime(2023, 11, 15, tzinfo=timezone.utc)
    info.downloads = downloads
    return info


_SQUAD_README = """
# SQuAD: Stanford Question Answering Dataset

SQuAD is a reading comprehension dataset consisting of questions posed by
crowdworkers on Wikipedia articles.

## Dataset Card

### Bias Analysis and Limitations

This dataset was collected from Wikipedia and may contain demographic bias
and underrepresented viewpoints. Workers on Mechanical Turk may introduce
additional annotation bias. We encourage fairness audits before deployment.

## Citation

```bibtex
@article{rajpurkar2016squad,
  title={Squad: 100,000+ questions for machine comprehension of text},
  author={Rajpurkar, Pranav and Zhang, Jian and Lopyrev, Konstantin and Liang, Percy},
  journal={arXiv preprint arXiv:1606.05250},
  year={2016}
}
```
"""

_MINIMAL_README = "# My Dataset\n\nA simple dataset."


# ---------------------------------------------------------------------------
# _has_bias_content() unit tests
# ---------------------------------------------------------------------------

class TestHasBiasContent:
    def test_detects_bias_keyword(self):
        assert _has_bias_content("This dataset may contain bias in annotations.") is True

    def test_detects_fairness(self):
        assert _has_bias_content("Fairness considerations were taken into account.") is True

    def test_detects_demographic(self):
        assert _has_bias_content("Demographic distribution was measured.") is True

    def test_detects_underrepresented(self):
        assert _has_bias_content("Underrepresented groups may be present.") is True

    def test_detects_discrimination(self):
        assert _has_bias_content("Discrimination risks were evaluated.") is True

    def test_detects_limitation(self):
        assert _has_bias_content("Limitation: this data skews towards English.") is True

    def test_no_bias_keywords(self):
        assert _has_bias_content("A collection of Wikipedia articles.") is False

    def test_empty_string(self):
        assert _has_bias_content("") is False

    def test_case_insensitive(self):
        assert _has_bias_content("BIAS and FAIRNESS analysis.") is True

    def test_squad_readme_has_bias(self):
        assert _has_bias_content(_SQUAD_README) is True

    def test_minimal_readme_no_bias(self):
        assert _has_bias_content(_MINIMAL_README) is False


# ---------------------------------------------------------------------------
# _extract_citation() unit tests
# ---------------------------------------------------------------------------

class TestExtractCitation:
    def test_extracts_bibtex(self):
        citation = _extract_citation(_SQUAD_README)
        assert citation is not None
        assert "@article" in citation
        assert "rajpurkar2016squad" in citation

    def test_returns_none_when_no_bibtex(self):
        assert _extract_citation(_MINIMAL_README) is None

    def test_empty_string(self):
        assert _extract_citation("") is None

    def test_extracts_inproceedings(self):
        text = """
@inproceedings{author2023,
  title={Great Paper},
  author={Author, A},
  year={2023}
}
"""
        citation = _extract_citation(text)
        assert citation is not None
        assert "@inproceedings" in citation


# ---------------------------------------------------------------------------
# _parse_hf_tags() unit tests
# ---------------------------------------------------------------------------

class TestParseHfTags:
    def test_namespaced_tags_split(self):
        buckets = _parse_hf_tags(["language:en", "license:apache-2.0"])
        assert buckets["language"] == ["en"]
        assert buckets["license"] == ["apache-2.0"]

    def test_bare_tags_in_other(self):
        buckets = _parse_hf_tags(["nlp", "research"])
        assert "nlp" in buckets["other"]

    def test_multiple_values_same_namespace(self):
        buckets = _parse_hf_tags(["language:en", "language:fr"])
        assert set(buckets["language"]) == {"en", "fr"}

    def test_empty_list(self):
        assert _parse_hf_tags([]) == {}

    def test_none_handled(self):
        assert _parse_hf_tags(None) == {}


# ---------------------------------------------------------------------------
# _build_dataset_provenance() unit tests
# ---------------------------------------------------------------------------

class TestBuildDatasetProvenance:
    def test_returns_dataset_provenance(self):
        info = _make_dataset_info()
        prov = _build_dataset_provenance(info, "squad", _SQUAD_README)
        assert isinstance(prov, DatasetProvenance)

    def test_dataset_id_set(self):
        info = _make_dataset_info("squad")
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.dataset_id == "squad"

    def test_source_is_huggingface(self):
        info = _make_dataset_info()
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.source == "huggingface"

    def test_license_from_card_data(self):
        cd = _make_card_data(license="cc-by-4.0")
        info = _make_dataset_info(card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.license == "cc-by-4.0"

    def test_license_falls_back_to_tags(self):
        cd = _make_card_data(license=None)
        cd.license = None
        info = _make_dataset_info(tags=["license:mit"], card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.license == "mit"

    def test_languages_from_card_data(self):
        cd = _make_card_data(language=["en", "fr"])
        info = _make_dataset_info(card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert "en" in prov.languages
        assert "fr" in prov.languages

    def test_task_categories_extracted(self):
        cd = _make_card_data(task_categories=["text-generation", "summarization"])
        info = _make_dataset_info(card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert "text-generation" in prov.task_categories

    def test_size_category_first_entry(self):
        cd = _make_card_data(size_categories=["1M<n<10M", "100K<n<1M"])
        info = _make_dataset_info(card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.size_category == "1M<n<10M"

    def test_source_datasets_extracted(self):
        cd = _make_card_data(source_datasets=["common_crawl", "wikipedia"])
        info = _make_dataset_info(card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert "common_crawl" in prov.source_datasets

    def test_downloads_recorded(self):
        info = _make_dataset_info(downloads=1_234_567)
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.downloads == 1_234_567

    def test_created_at_iso_string(self):
        dt = datetime(2021, 6, 1, tzinfo=timezone.utc)
        info = _make_dataset_info(created_at=dt)
        prov = _build_dataset_provenance(info, "squad", None)
        assert "2021" in prov.created_at

    def test_bias_detected_from_readme(self):
        info = _make_dataset_info()
        prov = _build_dataset_provenance(info, "squad", _SQUAD_README)
        assert prov.has_bias_analysis is True

    def test_no_bias_when_no_card(self):
        info = _make_dataset_info()
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.has_bias_analysis is False

    def test_citation_extracted_from_readme(self):
        info = _make_dataset_info()
        prov = _build_dataset_provenance(info, "squad", _SQUAD_README)
        assert prov.citation is not None
        assert "rajpurkar" in prov.citation

    def test_pretty_name_from_card_data(self):
        cd = _make_card_data(pretty_name="Stanford QA")
        info = _make_dataset_info(card_data=cd)
        prov = _build_dataset_provenance(info, "squad", None)
        assert prov.pretty_name == "Stanford QA"

    def test_card_data_raw_populated(self):
        info = _make_dataset_info()
        prov = _build_dataset_provenance(info, "squad", None)
        assert isinstance(prov.card_data_raw, dict)


# ---------------------------------------------------------------------------
# DatasetProvenance.completeness_score() tests
# ---------------------------------------------------------------------------

class TestCompletenessScore:
    def _full_prov(self) -> DatasetProvenance:
        return DatasetProvenance(
            dataset_id="squad",
            source="huggingface",
            description="A QA dataset.",
            license="cc-by-4.0",
            languages=["en"],
            task_categories=["question-answering"],
            size_category="10K<n<100K",
            source_datasets=["wikipedia"],
            has_bias_analysis=True,
            citation="@article{r2016}",
        )

    def test_full_record_scores_100(self):
        assert self._full_prov().completeness_score() == 100

    def test_missing_description_reduces_score(self):
        p = self._full_prov()
        p.description = None
        assert p.completeness_score() < 100
        assert p.completeness_score() == 80  # 100 - 20

    def test_missing_license_reduces_score(self):
        p = self._full_prov()
        p.license = None
        assert p.completeness_score() == 80  # 100 - 20

    def test_missing_languages_reduces_score(self):
        p = self._full_prov()
        p.languages = []
        assert p.completeness_score() == 85  # 100 - 15

    def test_empty_dataset_scores_zero(self):
        p = DatasetProvenance(dataset_id="x", source="huggingface")
        assert p.completeness_score() == 0

    def test_score_capped_at_100(self):
        p = self._full_prov()
        # Artificially set everything True
        assert p.completeness_score() <= 100

    def test_partial_record_midrange(self):
        p = DatasetProvenance(
            dataset_id="x",
            source="huggingface",
            license="mit",
            languages=["en"],
        )
        score = p.completeness_score()
        assert 0 < score < 100


# ---------------------------------------------------------------------------
# DatasetProvenance.completeness_gaps() tests
# ---------------------------------------------------------------------------

class TestCompletenessGaps:
    def test_full_record_no_gaps(self):
        p = DatasetProvenance(
            dataset_id="sq",
            source="huggingface",
            description="desc",
            license="mit",
            languages=["en"],
            task_categories=["qa"],
            size_category="10K<n<100K",
            source_datasets=["wiki"],
            has_bias_analysis=True,
            citation="@article{x}",
        )
        assert p.completeness_gaps() == []

    def test_missing_license_in_gaps(self):
        p = DatasetProvenance(dataset_id="x", source="huggingface")
        gaps = p.completeness_gaps()
        assert any("license" in g.lower() or "provenance" in g.lower() for g in gaps)

    def test_missing_bias_analysis_in_gaps(self):
        p = DatasetProvenance(dataset_id="x", source="huggingface")
        gaps = p.completeness_gaps()
        assert any("bias" in g.lower() for g in gaps)

    def test_returns_list(self):
        p = DatasetProvenance(dataset_id="x", source="huggingface")
        assert isinstance(p.completeness_gaps(), list)


# ---------------------------------------------------------------------------
# DatasetProvenance.annex_iv_section_2a() tests
# ---------------------------------------------------------------------------

class TestAnnexIvSection2a:
    def _prov(self) -> DatasetProvenance:
        return DatasetProvenance(
            dataset_id="squad",
            source="huggingface",
            license="cc-by-4.0",
            languages=["en"],
            task_categories=["question-answering"],
            size_category="10K<n<100K",
            source_datasets=["wikipedia"],
            has_bias_analysis=True,
        )

    def test_section_key(self):
        assert self._prov().annex_iv_section_2a()["annex_iv_section"] == "2a"

    def test_title_present(self):
        assert "title" in self._prov().annex_iv_section_2a()

    def test_dataset_id_in_output(self):
        assert self._prov().annex_iv_section_2a()["dataset_id"] == "squad"

    def test_license_in_output(self):
        assert self._prov().annex_iv_section_2a()["license"] == "cc-by-4.0"

    def test_bias_analysis_block(self):
        section = self._prov().annex_iv_section_2a()
        assert "bias_analysis" in section
        assert section["bias_analysis"]["has_bias_content_in_card"] is True

    def test_no_bias_note_warns(self):
        p = DatasetProvenance(dataset_id="x", source="huggingface")
        note = p.annex_iv_section_2a()["bias_analysis"]["note"]
        assert "required" in note.lower() or "No bias" in note

    def test_completeness_block(self):
        section = self._prov().annex_iv_section_2a()
        assert "completeness" in section
        assert "score" in section["completeness"]
        assert "gaps" in section["completeness"]

    def test_to_dict_alias(self):
        p = self._prov()
        assert p.to_dict() == p.annex_iv_section_2a()


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_huggingface_dataset() integration tests
# ---------------------------------------------------------------------------

class TestFromHuggingfaceDataset:
    @pytest.fixture()
    def mock_hf_env(self):
        """Patch HfApi and DatasetCard to avoid all network calls."""
        info = _make_dataset_info("squad")
        mock_api = MagicMock()
        mock_api.return_value.dataset_info.return_value = info

        mock_card = MagicMock()
        mock_card.content = _SQUAD_README

        with patch("huggingface_hub.HfApi", mock_api), \
             patch("huggingface_hub.DatasetCard") as mock_dc_cls:
            mock_dc_cls.load.return_value = mock_card
            yield info, mock_api, mock_dc_cls

    def test_returns_dataset_provenance(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        assert isinstance(prov, DatasetProvenance)

    def test_dataset_id_correct(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        assert prov.dataset_id == "squad"

    def test_source_is_huggingface(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        assert prov.source == "huggingface"

    def test_bias_detected_via_readme(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        assert prov.has_bias_analysis is True

    def test_citation_extracted(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        assert prov.citation is not None

    def test_completeness_score_positive(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        assert prov.completeness_score() > 0

    def test_card_load_failure_handled_gracefully(self):
        """DatasetCard.load() failure must not crash — metadata alone is enough."""
        info = _make_dataset_info("squad")
        mock_api = MagicMock()
        mock_api.return_value.dataset_info.return_value = info

        with patch("huggingface_hub.HfApi", mock_api), \
             patch("huggingface_hub.DatasetCard") as mock_dc_cls:
            mock_dc_cls.load.side_effect = Exception("README not found")
            prov = ArtifactExtractor.from_huggingface_dataset("squad")

        assert isinstance(prov, DatasetProvenance)
        assert prov.has_bias_analysis is False  # no card content
        assert prov.citation is None

    def test_missing_huggingface_hub_raises_import_error(self):
        with patch.dict(sys.modules, {"huggingface_hub": None}):
            with pytest.raises(ImportError, match="huggingface_hub is required"):
                ArtifactExtractor.from_huggingface_dataset("squad")

    def test_annex_iv_section_2a_complete(self, mock_hf_env):
        prov = ArtifactExtractor.from_huggingface_dataset("squad")
        section = prov.annex_iv_section_2a()
        assert section["annex_iv_section"] == "2a"
        assert "completeness" in section


# ---------------------------------------------------------------------------
# ArtifactExtractor.from_huggingface_dataset_list() tests
# ---------------------------------------------------------------------------

class TestFromHuggingfaceDatasetList:
    def _mock_env(self, dataset_ids):
        """Patch HfApi to return a distinct mock info per dataset id."""
        infos = {did: _make_dataset_info(did) for did in dataset_ids}

        def _dataset_info(repo_id, **kwargs):
            return infos[repo_id]

        mock_api = MagicMock()
        mock_api.return_value.dataset_info.side_effect = _dataset_info
        mock_card = MagicMock()
        mock_card.content = _MINIMAL_README
        return mock_api, mock_card

    def test_returns_list_of_dataset_provenance(self):
        ids = ["squad", "wikitext"]
        mock_api, mock_card = self._mock_env(ids)
        with patch("huggingface_hub.HfApi", mock_api), \
             patch("huggingface_hub.DatasetCard") as dc_cls:
            dc_cls.load.return_value = mock_card
            results = ArtifactExtractor.from_huggingface_dataset_list(ids)
        assert len(results) == 2
        assert all(isinstance(r, DatasetProvenance) for r in results)

    def test_order_preserved(self):
        ids = ["squad", "wikitext", "c4"]
        mock_api, mock_card = self._mock_env(ids)
        with patch("huggingface_hub.HfApi", mock_api), \
             patch("huggingface_hub.DatasetCard") as dc_cls:
            dc_cls.load.return_value = mock_card
            results = ArtifactExtractor.from_huggingface_dataset_list(ids)
        assert [r.dataset_id for r in results] == ids

    def test_partial_failure_returns_fallback_record(self):
        mock_api = MagicMock()
        mock_api.return_value.dataset_info.side_effect = [
            _make_dataset_info("squad"),
            Exception("dataset not found"),
        ]
        mock_card = MagicMock()
        mock_card.content = _MINIMAL_README
        with patch("huggingface_hub.HfApi", mock_api), \
             patch("huggingface_hub.DatasetCard") as dc_cls:
            dc_cls.load.return_value = mock_card
            results = ArtifactExtractor.from_huggingface_dataset_list(["squad", "bad-dataset"])
        assert len(results) == 2
        assert results[0].dataset_id == "squad"
        assert results[1].dataset_id == "bad-dataset"
        assert "extraction_error" in results[1].card_data_raw

    def test_empty_list(self):
        results = ArtifactExtractor.from_huggingface_dataset_list([])
        assert results == []


# ---------------------------------------------------------------------------
# ArtifactExtractionResult.datasets integration tests
# ---------------------------------------------------------------------------

class TestArtifactExtractionResultDatasets:
    def _prov(self, did: str = "squad") -> DatasetProvenance:
        return DatasetProvenance(
            dataset_id=did,
            source="huggingface",
            license="mit",
            languages=["en"],
        )

    def test_empty_with_no_datasets(self):
        r = ArtifactExtractionResult()
        assert r.is_empty()

    def test_not_empty_when_datasets_present(self):
        r = ArtifactExtractionResult(datasets=[self._prov()])
        assert not r.is_empty()

    def test_section_2a_in_annex_iv_dict(self):
        r = ArtifactExtractionResult(datasets=[self._prov()])
        d = r.to_annex_iv_dict()
        assert "section_2a" in d

    def test_section_2a_is_list(self):
        r = ArtifactExtractionResult(datasets=[self._prov("squad"), self._prov("c4")])
        d = r.to_annex_iv_dict()
        assert len(d["section_2a"]) == 2

    def test_all_three_sections_present(self):
        from squash.artifact_extractor import TrainingMetrics, TrainingConfig
        r = ArtifactExtractionResult(
            config=TrainingConfig(source_path=None, optimizer={"type": "Adam"}),
            datasets=[self._prov()],
            metrics=TrainingMetrics(source="tb", run_id=None),
        )
        d = r.to_annex_iv_dict()
        assert "section_1c" in d
        assert "section_2a" in d
        assert "section_3b" in d
