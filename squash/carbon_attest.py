"""squash/carbon_attest.py — Track C / C9 — Carbon / Energy Attestation.

Sprint 36 (W259–W261).

ESG / sustainability offices are a new buyer motion for AI governance tooling.
CSRD applies to all large EU companies from 2025. The EU AI Act will require
energy and life-cycle impact reporting for large AI systems. OMB issued its
AI data-centre lifecycle reporting rule in January 2025.

Squash carbon attestation is the machine-readable, cryptographically signed
proof of energy + CO₂ impact that these frameworks demand. One command,
embedded in CI, producing an artifact auditors and sustainability offices
accept.

Regulatory anchors
------------------
* **CSRD (EU Corporate Sustainability Reporting Directive)** — large EU
  companies must report Scope 2 (purchased electricity) and Scope 3 (value
  chain) emissions from 2025. AI inference is a Scope 2 / Scope 3 source.
* **EU AI Act** — Annex IV §4 requires training compute + energy; Article 9
  risk management must consider environmental impact for high-risk systems.
* **CSDDD (EU Corporate Sustainability Due Diligence Directive)** — supply
  chain sustainability obligations that extend to AI vendor emissions.
* **UK PRA SS1/23** — climate risk management guidance requiring quantified
  operational emissions including digital infrastructure.
* **OMB DOE rule (Jan 2025)** — federal agencies must report AI-system
  energy and lifecycle data.

Architecture (W259)
-------------------

    ModelArchitecture  — TRANSFORMER | CNN | RNN | MOE | DIFFUSION | EMBEDDING | UNKNOWN
    HardwareType       — A100 | H100 | TPU_V4 | TPU_V5 | RTX4090 | CPU | UNKNOWN
    EnergyScope        — SCOPE_2 | SCOPE_3 | COMBINED

    FlopEstimate       — FLOPs/inference + method used
    GridIntensity      — gCO₂eq/kWh for a region (static + optional live)
    EnergyEstimate     — kWh/inference, kWh/1M-tokens
    CarbonAttestation  — full signed certificate

W259: FLOP estimator × carbon intensity × compute engine
W260: CSRD / CSDDD / UK PRA SS1/23 field mapping
W261: CLI + ML-BOM CycloneDX enrichment

Usage
-----
::

    cert = CarbonAttestation.compute(
        model_id="bert-base-uncased",
        param_count=110_000_000,
        deployment_region="eu-west-1",
        hardware=HardwareType.A100,
        inferences_per_day=100_000,
    )
    print(cert.co2_grams_per_inference, "gCO₂eq/inference")
    print(cert.to_csrd()["scope_2_tco2eq_per_year"])

    # With CSRD report
    report = cert.to_csrd()

    # With ML-BOM enrichment
    enriched_bom = enrich_mlbom(bom_path, cert)
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import math
import os
import sqlite3
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

_DEFAULT_CACHE_DB = Path.home() / ".squash" / "carbon_cache.db"


# ── Enumerations ──────────────────────────────────────────────────────────────


class ModelArchitecture(str, Enum):
    TRANSFORMER = "transformer"
    CNN         = "cnn"
    RNN         = "rnn"
    MOE         = "moe"             # Mixture of Experts
    DIFFUSION   = "diffusion"
    EMBEDDING   = "embedding"
    UNKNOWN     = "unknown"


class HardwareType(str, Enum):
    A100    = "a100"
    H100    = "h100"
    H200    = "h200"
    TPU_V4  = "tpu_v4"
    TPU_V5  = "tpu_v5"
    RTX4090 = "rtx4090"
    CPU     = "cpu"
    UNKNOWN = "unknown"


class EnergyScope(str, Enum):
    SCOPE_2  = "scope_2"    # purchased electricity
    SCOPE_3  = "scope_3"    # value chain (embodied carbon)
    COMBINED = "combined"


# ── Hardware efficiency table ─────────────────────────────────────────────────
# TFLOPS/Watt (FP16 or BF16 throughput / TDP).  Sources: product datasheets.
#
#   NVIDIA A100 SXM: 312 TFLOPS FP16 / 400W TDP = 0.78 TFLOPS/W
#   NVIDIA H100 SXM: 989 TFLOPS FP16 / 700W TDP = 1.41 TFLOPS/W
#   NVIDIA H200:     ~1400 TFLOPS FP16 / 700W    = 2.00 TFLOPS/W (est.)
#   Google TPU v4:   275 TFLOPS BF16 / 170W      = 1.62 TFLOPS/W
#   Google TPU v5e:  393 TFLOPS BF16 / 163W      = 2.41 TFLOPS/W
#   NVIDIA RTX 4090: 165 TFLOPS FP16 / 450W      = 0.37 TFLOPS/W
#   x86 CPU:         ~0.5 TFLOPS FP16 / 150W     = 0.003 TFLOPS/W (rough)

_HARDWARE_EFF: dict[HardwareType, float] = {
    HardwareType.A100:    0.78,
    HardwareType.H100:    1.41,
    HardwareType.H200:    2.00,
    HardwareType.TPU_V4:  1.62,
    HardwareType.TPU_V5:  2.41,
    HardwareType.RTX4090: 0.37,
    HardwareType.CPU:     0.003,
    HardwareType.UNKNOWN: 0.50,   # conservative mid-range estimate
}

# PUE (Power Usage Effectiveness) per provider.
_PUE: dict[str, float] = {
    "aws": 1.20,
    "gcp": 1.10,
    "azure": 1.18,
    "on-premise": 1.60,  # industry average data-centre
    "default": 1.20,
}


# ── Regional carbon intensity (gCO₂eq/kWh) ───────────────────────────────────
# Static baseline table. Sources: IEA 2023 Electricity Map; EPA eGRID 2022;
# Carbon Footprint Ltd regional grid factors 2023/2024.
# Values in gCO₂eq per kWh — location-based (grid average).

_GRID_INTENSITY: dict[str, float] = {
    # AWS regions
    "us-east-1":         386.0,   # N. Virginia (PJM)
    "us-east-2":         404.0,   # Ohio (MISO)
    "us-west-1":         218.0,   # N. California
    "us-west-2":         63.0,    # Oregon (high hydro)
    "ca-central-1":      14.0,    # Canada (Quebec, hydro)
    "eu-west-1":         268.0,   # Ireland
    "eu-west-2":         233.0,   # London
    "eu-west-3":         57.0,    # Paris (nuclear-heavy)
    "eu-central-1":      311.0,   # Frankfurt
    "eu-central-2":      57.0,    # Zurich
    "eu-north-1":        8.0,     # Stockholm (hydro/wind)
    "eu-south-1":        233.0,   # Milan
    "eu-south-2":        165.0,   # Spain
    "ap-northeast-1":    506.0,   # Tokyo
    "ap-northeast-2":    415.0,   # Seoul
    "ap-northeast-3":    506.0,   # Osaka
    "ap-southeast-1":    408.0,   # Singapore
    "ap-southeast-2":    656.0,   # Sydney (coal-heavy)
    "ap-southeast-3":    724.0,   # Jakarta
    "ap-south-1":        708.0,   # Mumbai
    "ap-east-1":         570.0,   # Hong Kong
    "me-south-1":        622.0,   # Bahrain
    "af-south-1":        928.0,   # Cape Town (coal)
    "sa-east-1":         74.0,    # São Paulo (hydro)
    "il-central-1":      522.0,   # Israel
    # GCP regions
    "us-central1":       368.0,   # Iowa
    "us-east1":          480.0,   # S. Carolina
    "us-east4":          386.0,   # N. Virginia
    "us-west1":          63.0,    # Oregon
    "us-west2":          218.0,   # Los Angeles
    "us-west3":          418.0,   # Salt Lake City
    "us-west4":          427.0,   # Las Vegas
    "northamerica-northeast1": 14.0,  # Montréal
    "northamerica-northeast2": 14.0,  # Toronto
    "europe-west1":      145.0,   # Belgium
    "europe-west2":      233.0,   # London
    "europe-west3":      311.0,   # Frankfurt
    "europe-west4":      344.0,   # Netherlands
    "europe-west6":      57.0,    # Zurich
    "europe-west8":      233.0,   # Milan
    "europe-west9":      57.0,    # Paris
    "europe-central2":   712.0,   # Warsaw (coal)
    "europe-north1":     8.0,     # Finland
    "europe-southwest1": 165.0,   # Madrid
    "asia-east1":        505.0,   # Taiwan
    "asia-east2":        570.0,   # Hong Kong
    "asia-northeast1":   506.0,   # Tokyo
    "asia-northeast2":   506.0,   # Osaka
    "asia-northeast3":   415.0,   # Seoul
    "asia-south1":       708.0,   # Mumbai
    "asia-south2":       708.0,   # Delhi
    "asia-southeast1":   408.0,   # Singapore
    "asia-southeast2":   724.0,   # Jakarta
    "australia-southeast1": 656.0, # Sydney
    "southamerica-east1": 74.0,   # São Paulo
    # Azure regions
    "eastus":            386.0,
    "eastus2":           386.0,
    "westus":            218.0,
    "westus2":           63.0,
    "westus3":           418.0,
    "centralus":         368.0,
    "northcentralus":    404.0,
    "southcentralus":    430.0,
    "westcentralus":     418.0,
    "canadacentral":     14.0,
    "canadaeast":        14.0,
    "northeurope":       268.0,   # Dublin
    "westeurope":        344.0,   # Netherlands
    "uksouth":           233.0,
    "ukwest":            233.0,
    "francecentral":     57.0,
    "francesouth":       57.0,
    "germanywestcentral": 311.0,
    "switzerlandnorth":  57.0,
    "swedencentral":     8.0,
    "norwayeast":        8.0,
    "finlandcentral":    8.0,
    "polandcentral":     712.0,
    "italynorth":        233.0,
    "spaincentral":      165.0,
    "eastasia":          570.0,
    "southeastasia":     408.0,
    "japaneast":         506.0,
    "japanwest":         506.0,
    "koreacentral":      415.0,
    "australiaeast":     656.0,
    "centralindia":      708.0,
    "brazilsouth":       74.0,
    "southafricanorth":  928.0,
    # Sovereign / country codes (ISO 3166-1 alpha-2)
    "de": 311.0,   # Germany
    "fr": 57.0,    # France
    "gb": 233.0,   # UK
    "us": 386.0,   # USA (average)
    "cn": 590.0,   # China
    "in": 708.0,   # India
    "au": 656.0,   # Australia
    "jp": 506.0,   # Japan
    "kr": 415.0,   # South Korea
    "br": 74.0,    # Brazil
    "se": 8.0,     # Sweden
    "no": 8.0,     # Norway
    "fi": 8.0,     # Finland
    "ch": 57.0,    # Switzerland
}

# Global average fallback (IEA 2022 global electricity mix)
_GLOBAL_AVERAGE_INTENSITY = 436.0  # gCO₂eq/kWh


# ── FLOP estimation (W259) ────────────────────────────────────────────────────
# FLOPs per inference for the forward pass of common architecture families.
# Convention: FLOPs = multiply-accumulate count × 2.
# Sources: Kaplan et al. (2020), Hoffmann et al. (2022 Chinchilla), MLPerf.

@dataclass
class FlopEstimate:
    flops: float                    # total FLOPs for one forward pass
    method: str                     # derivation method
    architecture: ModelArchitecture
    confidence: str = "medium"      # low | medium | high


def estimate_flops(
    param_count: int,
    architecture: ModelArchitecture = ModelArchitecture.TRANSFORMER,
    seq_len: int = 512,
    batch_size: int = 1,
) -> FlopEstimate:
    """Estimate FLOPs per inference for a given model.

    Derivations
    -----------
    Transformer (decoder / encoder-decoder):
        FLOPs ≈ 2 × N × L  where N = params, L = seq_len
        (Kaplan et al. 2020: each parameter touched twice per token)
        For a batch: × batch_size

    CNN (ResNet-style):
        FLOPs ≈ 2 × N × (output_feature_size)
        Approximated as 2 × N × 1 (single classification forward pass)

    Embedding models (BERT-style, biencoder):
        FLOPs ≈ 2 × N × seq_len  (same as transformer, shorter seq typical)

    MoE (Mixture of Experts):
        Active params ≈ N / expert_count (typically N / 8 for sparse routing)
        FLOPs ≈ 2 × (N / 8) × seq_len

    Diffusion (UNet-based):
        FLOPs ≈ 2 × N × n_timesteps  (default 20 DDIM steps)

    RNN / LSTM:
        FLOPs ≈ 2 × N × seq_len  (unrolled, similar to transformer)
    """
    p = float(param_count)

    if architecture == ModelArchitecture.TRANSFORMER:
        flops = 2.0 * p * seq_len * batch_size
        method = "2·N·L (Kaplan et al. 2020)"
        confidence = "high"

    elif architecture == ModelArchitecture.EMBEDDING:
        # Shorter sequence typical for embedding models
        eff_seq = min(seq_len, 128)
        flops = 2.0 * p * eff_seq * batch_size
        method = "2·N·L (embedding, L=min(seq_len,128))"
        confidence = "high"

    elif architecture == ModelArchitecture.MOE:
        # Sparse routing activates ~1/8 of total params
        active = p / 8.0
        flops = 2.0 * active * seq_len * batch_size
        method = "2·(N/8)·L (MoE sparse routing)"
        confidence = "medium"

    elif architecture == ModelArchitecture.DIFFUSION:
        # 20 DDIM denoising steps is a common inference config
        timesteps = 20
        flops = 2.0 * p * timesteps * batch_size
        method = f"2·N·T_steps (diffusion, T={timesteps})"
        confidence = "medium"

    elif architecture == ModelArchitecture.CNN:
        # CNNs are compute-bound differently; rough approximation
        flops = 2.0 * p * batch_size
        method = "2·N (CNN, no sequence dimension)"
        confidence = "low"

    elif architecture == ModelArchitecture.RNN:
        flops = 2.0 * p * seq_len * batch_size
        method = "2·N·L (RNN unrolled)"
        confidence = "medium"

    else:
        # Unknown — use transformer formula as conservative estimate
        flops = 2.0 * p * seq_len * batch_size
        method = "2·N·L (fallback, architecture unknown)"
        confidence = "low"

    return FlopEstimate(
        flops=flops,
        method=method,
        architecture=architecture,
        confidence=confidence,
    )


# ── Grid intensity lookup (W259) ──────────────────────────────────────────────


@dataclass
class GridIntensity:
    region: str
    gco2_per_kwh: float
    source: str       # "static_table" | "electricity_maps_live" | "global_average"
    fetched_at: str


class CarbonIntensityCache:
    """SQLite cache for live Electricity Maps API responses.

    Falls back to the built-in static table when the API is unavailable
    or when SQUASH_CARBON_OFFLINE=1 is set. Cache TTL: 1 hour.
    """

    _TTL_SECONDS = 3600

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_CACHE_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS carbon_intensity (
                region      TEXT PRIMARY KEY,
                gco2_per_kwh REAL NOT NULL,
                source      TEXT NOT NULL,
                fetched_at  TEXT NOT NULL
            )
        """)
        self._conn.commit()

    def get(self, region: str) -> GridIntensity | None:
        row = self._conn.execute(
            "SELECT gco2_per_kwh, source, fetched_at FROM carbon_intensity WHERE region=?",
            (region,),
        ).fetchone()
        if row is None:
            return None
        gco2, source, fetched_at = row
        # Expire stale entries
        try:
            fetched = datetime.datetime.fromisoformat(fetched_at)
            age = (datetime.datetime.now(datetime.timezone.utc) - fetched).total_seconds()
            if age > self._TTL_SECONDS:
                return None
        except ValueError:
            return None
        return GridIntensity(region=region, gco2_per_kwh=gco2,
                             source=source, fetched_at=fetched_at)

    def put(self, gi: GridIntensity) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO carbon_intensity (region, gco2_per_kwh, source, fetched_at) "
            "VALUES (?, ?, ?, ?)",
            (gi.region, gi.gco2_per_kwh, gi.source, gi.fetched_at),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


def lookup_grid_intensity(
    region: str,
    cache: CarbonIntensityCache | None = None,
    live: bool = False,
) -> GridIntensity:
    """Return grid carbon intensity for a deployment region.

    Lookup order:
    1. SQLite cache (if fresh, ≤1h old)
    2. Electricity Maps API (if `live=True` and SQUASH_ELECTRICITY_MAPS_KEY set)
    3. Built-in static table
    4. Global average fallback (436 gCO₂eq/kWh)
    """
    now = _utc_now()
    key = region.lower().strip()

    if cache:
        cached = cache.get(key)
        if cached:
            return cached

    if live and not os.environ.get("SQUASH_CARBON_OFFLINE"):
        em_key = os.environ.get("SQUASH_ELECTRICITY_MAPS_KEY", "")
        if em_key:
            gi = _fetch_electricity_maps(key, em_key, now)
            if gi and cache:
                cache.put(gi)
            if gi:
                return gi

    # Built-in table
    intensity = _GRID_INTENSITY.get(key)
    if intensity is not None:
        gi = GridIntensity(region=key, gco2_per_kwh=intensity,
                           source="static_table", fetched_at=now)
        if cache:
            cache.put(gi)
        return gi

    # Global average fallback
    gi = GridIntensity(region=key, gco2_per_kwh=_GLOBAL_AVERAGE_INTENSITY,
                       source="global_average", fetched_at=now)
    if cache:
        cache.put(gi)
    return gi


def _fetch_electricity_maps(region: str, api_key: str, now: str) -> GridIntensity | None:
    """Attempt a live fetch from Electricity Maps API. Returns None on failure."""
    url = f"https://api.electricitymap.org/v3/carbon-intensity/latest?zone={region}"
    try:
        req = urllib.request.Request(url, headers={"auth-token": api_key})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        intensity = float(data.get("carbonIntensity", 0))
        return GridIntensity(region=region, gco2_per_kwh=intensity,
                             source="electricity_maps_live", fetched_at=now)
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, ValueError):
        return None


# ── Energy estimate (W259) ────────────────────────────────────────────────────


@dataclass
class EnergyEstimate:
    kwh_per_inference: float
    kwh_per_million_tokens: float
    flops_per_inference: float
    hardware: HardwareType
    hardware_efficiency_tflops_per_watt: float
    pue: float
    utilization_factor: float    # GPU/TPU utilization (0–1)
    method: str


def estimate_energy(
    flop_estimate: FlopEstimate,
    hardware: HardwareType = HardwareType.A100,
    utilization: float = 0.45,   # typical cloud inference utilization
    tokens_per_inference: int = 512,
    pue_override: float | None = None,
) -> EnergyEstimate:
    """Compute kWh per inference from FLOPs × hardware efficiency.

    E (Wh) = FLOPs / (efficiency × 10¹² W/TFLOPS × utilization)
    kWh    = E / 1000

    PUE multiplier accounts for cooling and overhead power.
    """
    eff = _HARDWARE_EFF.get(hardware, 0.50)
    pue = pue_override if pue_override is not None else _PUE["default"]

    # Joules = FLOPs / (TFLOPS/W × 10^12 × utilization)
    # kWh = joules / 3.6e6
    joules = flop_estimate.flops / (eff * 1e12 * max(utilization, 0.01))
    joules_with_pue = joules * pue
    kwh = joules_with_pue / 3_600_000.0

    # Scale to 1M tokens: tokens_per_inference is the average token count
    tokens = max(tokens_per_inference, 1)
    kwh_per_million = kwh * (1_000_000.0 / tokens)

    return EnergyEstimate(
        kwh_per_inference=kwh,
        kwh_per_million_tokens=kwh_per_million,
        flops_per_inference=flop_estimate.flops,
        hardware=hardware,
        hardware_efficiency_tflops_per_watt=eff,
        pue=pue,
        utilization_factor=utilization,
        method=f"FLOPs/{flop_estimate.method} × HW_eff={eff} TFLOPS/W × util={utilization} × PUE={pue}",
    )


# ── CarbonAttestation (W259 + W260) ──────────────────────────────────────────


@dataclass
class CarbonAttestation:
    """Signed carbon + energy certificate for one model in one region.

    W259: core compute fields.
    W260: CSRD / CSDDD / UK PRA field mapping via to_csrd() / to_regulatory().
    W261: ML-BOM enrichment via enrich_mlbom().
    """

    cert_id: str
    model_id: str
    deployment_region: str
    architecture: ModelArchitecture
    hardware: HardwareType
    param_count: int
    inferences_per_day: int
    tokens_per_inference: int

    # Energy
    kwh_per_inference: float
    kwh_per_million_tokens: float
    kwh_per_day: float
    kwh_per_year: float

    # Carbon (location-based, Scope 2)
    gco2_per_inference: float           # gCO₂eq
    co2_kg_per_day: float               # kgCO₂eq/day
    co2_tonne_per_year: float           # tCO₂eq/year

    # Carbon (market-based, optional — user-supplied RECs/PPAs)
    market_gco2_per_inference: float    # 0 if no market instrument declared
    market_co2_tonne_per_year: float

    # Grid
    grid_intensity_gco2_per_kwh: float
    grid_source: str

    # Provenance
    flop_estimate_method: str
    energy_method: str
    pue: float
    utilization_factor: float
    compute_timestamp: str
    signature: str = ""
    squash_version: str = VERSION

    # ── CSRD field mapping (W260) ──────────────────────────────────────────────

    def to_csrd(
        self,
        renewable_energy_fraction: float = 0.0,
        scope3_embodied_factor: float = 1.5,   # embodied carbon multiplier (typical: 1.2–2.0×)
    ) -> dict[str, Any]:
        """Map to CSRD Esrs E1 Scope 2 + Scope 3 reporting fields.

        CSRD ESRS E1-4 requires:
        - E1-4 §44(a): Scope 1 GHG emissions (not applicable for inference)
        - E1-4 §44(b): Scope 2 GHG — location-based AND market-based
        - E1-4 §44(c): Scope 3 GHG — Category 11 (use of sold products) or
                        Category 3 (fuel/energy activities) for AI services
        - E1-5: Energy consumption (total kWh, by source)
        - E1-7: Carbon removals and offsets

        Scope 3 estimated as scope_2 × scope3_embodied_factor (hardware
        manufacturing + network transmission; industry estimates 1.2–2.0×).
        """
        scope2_location_tco2 = self.co2_tonne_per_year
        scope2_market_tco2 = self.market_co2_tonne_per_year
        scope3_tco2 = scope2_location_tco2 * scope3_embodied_factor
        renewable_kwh = self.kwh_per_year * max(0.0, min(1.0, renewable_energy_fraction))
        grid_kwh = self.kwh_per_year - renewable_kwh

        return {
            "standard": "CSRD ESRS E1",
            "reporting_year": datetime.date.today().year,
            "model_id": self.model_id,
            "deployment_region": self.deployment_region,

            # E1-5: Energy
            "energy_total_kwh_year": round(self.kwh_per_year, 4),
            "energy_grid_kwh_year": round(grid_kwh, 4),
            "energy_renewable_kwh_year": round(renewable_kwh, 4),
            "energy_kwh_per_inference": round(self.kwh_per_inference, 10),
            "energy_kwh_per_million_tokens": round(self.kwh_per_million_tokens, 6),
            "inferences_per_day": self.inferences_per_day,

            # E1-4: GHG Scope 2 location-based
            "scope_2_location_tco2eq_per_year": round(scope2_location_tco2, 6),
            "scope_2_location_gco2_per_inference": round(self.gco2_per_inference, 6),
            "grid_intensity_gco2_per_kwh": self.grid_intensity_gco2_per_kwh,
            "grid_source": self.grid_source,

            # E1-4: GHG Scope 2 market-based
            "scope_2_market_tco2eq_per_year": round(scope2_market_tco2, 6),
            "renewable_energy_fraction": renewable_energy_fraction,

            # E1-4: GHG Scope 3 (Category 3 / 11 — estimated)
            "scope_3_tco2eq_per_year_estimated": round(scope3_tco2, 6),
            "scope3_embodied_factor_used": scope3_embodied_factor,
            "scope_3_methodology": (
                "Embodied carbon (hardware manufacturing + network) estimated as "
                f"scope_2_location × {scope3_embodied_factor:.1f}x factor per "
                "ADEME/IEA AI infrastructure guidance."
            ),

            # Combined
            "total_scope_2_3_tco2eq_per_year": round(scope2_location_tco2 + scope3_tco2, 6),

            # Provenance
            "squash_cert_id": self.cert_id,
            "compute_timestamp": self.compute_timestamp,
            "methodology_note": (
                f"Computed by squash carbon_attest v{VERSION}. "
                f"FLOPs: {self.flop_estimate_method}. "
                f"Hardware: {self.hardware.value} ({self.utilization_factor:.0%} utilization). "
                f"PUE: {self.pue}."
            ),
        }

    def to_regulatory(self, framework: str = "csrd") -> dict[str, Any]:
        """Return a framework-specific regulatory mapping.

        Supported: csrd | csddd | uk_pra_ss1_23 | omb_doe | eu_ai_act
        """
        base = self.to_csrd()
        fw = framework.lower().replace("-", "_").replace(" ", "_")

        if fw == "csddd":
            return {
                **base,
                "standard": "EU CSDDD (Corporate Sustainability Due Diligence Directive)",
                "csddd_article": "Article 15 — transition plans, including value chain emissions",
                "supplier_scope_3_tco2eq": base["scope_3_tco2eq_per_year_estimated"],
                "due_diligence_note": (
                    "CSDDD requires large companies to include significant suppliers' "
                    "Scope 3 emissions. This AI inference footprint should be disclosed "
                    "to downstream customers using squash as an AI supplier."
                ),
            }

        if fw in ("uk_pra_ss1_23", "pra"):
            return {
                **base,
                "standard": "UK PRA SS1/23 — Climate Risk Management",
                "climate_risk_category": "Physical and transition risk — operational emissions",
                "stranded_asset_note": (
                    "Data-centre equipment with embedded carbon may face stranded-asset "
                    "risk under rapid decarbonisation scenarios."
                ),
            }

        if fw in ("omb_doe", "doe"):
            return {
                **base,
                "standard": "OMB/DOE AI Data-Centre Lifecycle Reporting Rule (Jan 2025)",
                "agency_reporting_unit": self.model_id,
                "annual_kwh_per_model": round(self.kwh_per_year, 2),
                "annual_tco2eq_scope2": round(self.co2_tonne_per_year, 4),
                "doe_reporting_threshold_kwh": 1_000_000,
                "exceeds_reporting_threshold": self.kwh_per_year >= 1_000_000,
            }

        if fw in ("eu_ai_act", "eu_ai"):
            return {
                **base,
                "standard": "EU AI Act Annex IV §4 — Energy Consumption",
                "annex_iv_section": "§4 Training and testing compute + energy",
                "inference_energy_kwh_per_year": round(self.kwh_per_year, 2),
                "inference_co2_tco2eq_per_year": round(self.co2_tonne_per_year, 4),
                "eu_taxonomy_aligned": False,
                "taxonomy_note": (
                    "EU Taxonomy alignment requires additional assessment of "
                    "DNSH (Do No Significant Harm) criteria per Climate Delegated Act."
                ),
            }

        # Default: CSRD
        return base

    def to_dict(self) -> dict[str, Any]:
        return {
            "cert_id": self.cert_id,
            "model_id": self.model_id,
            "deployment_region": self.deployment_region,
            "architecture": self.architecture.value,
            "hardware": self.hardware.value,
            "param_count": self.param_count,
            "inferences_per_day": self.inferences_per_day,
            "tokens_per_inference": self.tokens_per_inference,
            "energy": {
                "kwh_per_inference": self.kwh_per_inference,
                "kwh_per_million_tokens": self.kwh_per_million_tokens,
                "kwh_per_day": self.kwh_per_day,
                "kwh_per_year": self.kwh_per_year,
            },
            "carbon": {
                "gco2_per_inference": self.gco2_per_inference,
                "co2_kg_per_day": self.co2_kg_per_day,
                "co2_tonne_per_year": self.co2_tonne_per_year,
                "market_gco2_per_inference": self.market_gco2_per_inference,
                "market_co2_tonne_per_year": self.market_co2_tonne_per_year,
                "grid_intensity_gco2_per_kwh": self.grid_intensity_gco2_per_kwh,
                "grid_source": self.grid_source,
            },
            "methodology": {
                "flop_estimate_method": self.flop_estimate_method,
                "energy_method": self.energy_method,
                "pue": self.pue,
                "utilization_factor": self.utilization_factor,
            },
            "compute_timestamp": self.compute_timestamp,
            "signature": self.signature,
            "squash_version": self.squash_version,
        }

    @classmethod
    def compute(
        cls,
        model_id: str,
        param_count: int,
        deployment_region: str = "us-east-1",
        architecture: ModelArchitecture = ModelArchitecture.TRANSFORMER,
        hardware: HardwareType = HardwareType.A100,
        inferences_per_day: int = 10_000,
        tokens_per_inference: int = 512,
        seq_len: int = 512,
        utilization: float = 0.45,
        pue_override: float | None = None,
        renewable_fraction: float = 0.0,
        live_intensity: bool = False,
        cache: CarbonIntensityCache | None = None,
        sign: bool = False,
    ) -> "CarbonAttestation":
        """Compute a full carbon attestation certificate.

        Parameters
        ----------
        model_id            : Model identifier (any string).
        param_count         : Total parameter count (e.g. 110_000_000 for BERT-base).
        deployment_region   : AWS/GCP/Azure region or ISO country code.
        architecture        : Model architecture family.
        hardware            : Inference hardware type.
        inferences_per_day  : Expected daily inference volume.
        tokens_per_inference: Average token count per inference (default: 512).
        seq_len             : Sequence length for FLOPs calculation.
        utilization         : GPU/TPU utilization fraction (default: 0.45).
        pue_override        : Override PUE value (default: 1.20).
        renewable_fraction  : Fraction of electricity from renewable sources.
        live_intensity      : Attempt live Electricity Maps fetch.
        cache               : Shared CarbonIntensityCache instance.
        sign                : HMAC-SHA256 sign the certificate.
        """
        flop_est = estimate_flops(param_count, architecture, seq_len)
        energy_est = estimate_energy(
            flop_est, hardware, utilization, tokens_per_inference, pue_override
        )
        grid = lookup_grid_intensity(deployment_region, cache, live_intensity)

        gco2_per_inference = energy_est.kwh_per_inference * grid.gco2_per_kwh
        co2_kg_per_day = gco2_per_inference * inferences_per_day / 1000.0
        co2_tonne_per_year = co2_kg_per_day * 365.25 / 1000.0

        # Market-based (renewable energy reduces effective emissions)
        market_gco2 = gco2_per_inference * (1.0 - max(0.0, min(1.0, renewable_fraction)))
        market_tonne_per_year = co2_tonne_per_year * (1.0 - renewable_fraction)

        kwh_per_day = energy_est.kwh_per_inference * inferences_per_day
        kwh_per_year = kwh_per_day * 365.25

        # Phase G.2: deterministic cert_id keyed on model identity + deployment.
        from squash.ids import cert_id as _cert_id
        _seed = {
            "model_id": model_id,
            "deployment_region": deployment_region,
            "architecture": architecture,
            "hardware": hardware,
            "param_count": param_count,
            "kwh_per_inference": round(energy_est.kwh_per_inference, 9),
        }
        cert = cls(
            cert_id=_cert_id("carbon", _seed),
            model_id=model_id,
            deployment_region=deployment_region,
            architecture=architecture,
            hardware=hardware,
            param_count=param_count,
            inferences_per_day=inferences_per_day,
            tokens_per_inference=tokens_per_inference,
            kwh_per_inference=energy_est.kwh_per_inference,
            kwh_per_million_tokens=energy_est.kwh_per_million_tokens,
            kwh_per_day=kwh_per_day,
            kwh_per_year=kwh_per_year,
            gco2_per_inference=gco2_per_inference,
            co2_kg_per_day=co2_kg_per_day,
            co2_tonne_per_year=co2_tonne_per_year,
            market_gco2_per_inference=market_gco2,
            market_co2_tonne_per_year=market_tonne_per_year,
            grid_intensity_gco2_per_kwh=grid.gco2_per_kwh,
            grid_source=grid.source,
            flop_estimate_method=flop_est.method,
            energy_method=energy_est.method,
            pue=energy_est.pue,
            utilization_factor=energy_est.utilization_factor,
            compute_timestamp=_utc_now(),
        )

        if sign:
            cert = cert.sign()
        return cert

    def sign(self, key: bytes | None = None) -> "CarbonAttestation":
        if key is None:
            key = _signing_key()
        # Phase G.2: RFC 8785 canonical bytes for the signed body.
        from squash.canon import canonical_bytes as _cb
        payload = _cb(self.to_dict())
        self.signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return self

    def verify(self, key: bytes | None = None) -> bool:
        if not self.signature:
            return False
        if key is None:
            key = _signing_key()
        from squash.canon import canonical_bytes as _cb
        sig = self.signature
        self.signature = ""
        payload = _cb(self.to_dict())
        self.signature = sig
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)


# ── ML-BOM enrichment (W261) ─────────────────────────────────────────────────


def enrich_mlbom(
    bom_path: Path,
    cert: CarbonAttestation,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Inject CarbonAttestation energy fields into a CycloneDX ML-BOM JSON.

    Adds an ``externalReferences`` entry and an ``environmentalConsiderations``
    block under the first component's metadata (or at the top-level BOM if no
    components). The CycloneDX 1.6+ AI/ML extension defines:

        metadata.component.environmentalConsiderations.energyConsumptions[*]
            activity: "inference"
            energyType: "purchased-electricity"
            energyConsumptionCase[*]
                case: "avg-case" / "high-case"
                value: <kwh>
                unit: "kWh"
            co2Equivalent
                value: <gco2>
                unit: "gCO2eq"

    This enrichment is idempotent — safe to call multiple times.
    """
    bom_path = Path(bom_path)
    try:
        bom = json.loads(bom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read ML-BOM at {bom_path}: {exc}") from exc

    env_block = {
        "squash_cert_id": cert.cert_id,
        "deployment_region": cert.deployment_region,
        "grid_intensity_gco2_per_kwh": cert.grid_intensity_gco2_per_kwh,
        "grid_source": cert.grid_source,
        "energyConsumptions": [{
            "activity": "inference",
            "energyType": "purchased-electricity",
            "energyConsumptionCase": [
                {
                    "case": "avg-case",
                    "value": cert.kwh_per_inference,
                    "unit": "kWh",
                    "note": f"Per inference ({cert.tokens_per_inference} tokens), "
                            f"{cert.hardware.value} @ {cert.utilization_factor:.0%} util",
                },
            ],
            "co2Equivalent": {
                "location_based": {
                    "value": cert.gco2_per_inference,
                    "unit": "gCO2eq",
                },
                "market_based": {
                    "value": cert.market_gco2_per_inference,
                    "unit": "gCO2eq",
                },
            },
            "per_million_tokens_kwh": cert.kwh_per_million_tokens,
            "annual_kwh_at_declared_scale": cert.kwh_per_year,
            "annual_co2_tonne_at_declared_scale": cert.co2_tonne_per_year,
        }],
    }

    # Inject into BOM
    if "components" in bom and bom["components"]:
        comp = bom["components"][0]
        comp.setdefault("environmentalConsiderations", {})
        comp["environmentalConsiderations"]["squash_carbon"] = env_block
    else:
        bom.setdefault("metadata", {})
        bom["metadata"]["squash_carbon"] = env_block

    # External reference to the squash cert
    bom.setdefault("externalReferences", [])
    # Remove stale squash-carbon reference if present
    bom["externalReferences"] = [
        r for r in bom["externalReferences"]
        if r.get("type") != "squash-carbon-attestation"
    ]
    bom["externalReferences"].append({
        "type": "squash-carbon-attestation",
        "url": f"squash://carbon/{cert.cert_id}",
        "comment": f"Carbon attestation — {cert.co2_tonne_per_year:.4f} tCO₂eq/year",
    })

    out = output_path or bom_path
    Path(out).write_text(json.dumps(bom, indent=2, ensure_ascii=False), encoding="utf-8")
    return bom


# ── Human-readable summary ────────────────────────────────────────────────────


def format_summary(cert: CarbonAttestation) -> str:
    """Return a concise human-readable summary for CLI output."""
    lines = [
        f"[squash attest-carbon] Carbon attestation — {cert.cert_id}",
        f"  Model:          {cert.model_id}",
        f"  Region:         {cert.deployment_region} "
        f"({cert.grid_intensity_gco2_per_kwh:.0f} gCO₂/kWh, {cert.grid_source})",
        f"  Hardware:       {cert.hardware.value}  "
        f"Architecture: {cert.architecture.value}  "
        f"Params: {cert.param_count / 1e6:.0f}M",
        f"  Energy/inference: {cert.kwh_per_inference * 1000:.4f} Wh  "
        f"({cert.kwh_per_million_tokens:.3f} kWh/1M tokens)",
        f"  CO₂/inference:  {cert.gco2_per_inference:.4f} gCO₂eq",
        f"  Scale ({cert.inferences_per_day:,}/day): "
        f"{cert.co2_kg_per_day:.3f} kgCO₂eq/day  "
        f"· {cert.co2_tonne_per_year:.4f} tCO₂eq/year",
        f"  CSRD Scope 2:   {cert.co2_tonne_per_year:.4f} tCO₂eq/year (location-based)",
        f"  CSRD Scope 2:   {cert.market_co2_tonne_per_year:.4f} tCO₂eq/year (market-based)",
    ]
    if cert.signature:
        lines.append(f"  Signature:      {cert.signature[:24]}…  ✓ signed")
    return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _signing_key() -> bytes:
    return os.environ.get("SQUASH_SIGNING_KEY", "squash-carbon-attest-key").encode()


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
