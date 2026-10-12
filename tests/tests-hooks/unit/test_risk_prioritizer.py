"""
Unit tests for hooks/components/risk_prioritizer.py
Validates 3-tier semantic classification across all 8 security disciplines,
quota allocation (25/20/5), dynamic backfilling, and Tier 2 boosting.
"""
from __future__ import annotations

from pathlib import Path

from hooks.components.risk_prioritizer import PrioritizationResult, RiskPrioritizer


def test_tier1_agent_governance_classification() -> None:
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path("AGENTS.md")) == 1
    assert prioritizer.get_tier(Path("CLAUDE.md")) == 1
    assert prioritizer.get_tier(Path(".cursorrules")) == 1
    assert prioritizer.get_tier(Path("mcp.json")) == 1
    assert prioritizer.get_tier(Path(".agent/settings.json")) == 1
    assert prioritizer.get_tier(Path(".husky/pre-commit")) == 1


def test_tier1_secrets_and_keys_classification() -> None:
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path(".env")) == 1
    assert prioritizer.get_tier(Path(".env.production")) == 1
    assert prioritizer.get_tier(Path("id_rsa")) == 1
    assert prioritizer.get_tier(Path("id_ed25519")) == 1
    assert prioritizer.get_tier(Path("server.pem")) == 1
    assert prioritizer.get_tier(Path("private.key")) == 1


def test_tier1_manifests_and_infra_classification() -> None:
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path("package.json")) == 1
    assert prioritizer.get_tier(Path("requirements.txt")) == 1
    assert prioritizer.get_tier(Path("pyproject.toml")) == 1
    assert prioritizer.get_tier(Path("Dockerfile")) == 1
    assert prioritizer.get_tier(Path(".github/workflows/deploy.yml")) == 1
    assert prioritizer.get_tier(Path("main.tf")) == 1


def test_tier2_security_code_and_entrypoints() -> None:
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path("auth_service.py")) == 2
    assert prioritizer.get_tier(Path("jwt_validator.ts")) == 2
    assert prioritizer.get_tier(Path("routes/api.go")) == 2
    assert prioritizer.get_tier(Path("controllers/user.py")) == 2
    assert prioritizer.get_tier(Path("server.js")) == 2
    assert prioritizer.get_tier(Path("main.py")) == 2
    assert prioritizer.get_tier(Path("utils/helper.py")) == 2


def test_tier3_lockfiles_and_docs() -> None:
    prioritizer = RiskPrioritizer()
    assert prioritizer.get_tier(Path("package-lock.json")) == 3
    assert prioritizer.get_tier(Path("yarn.lock")) == 3
    assert prioritizer.get_tier(Path("poetry.lock")) == 3
    assert prioritizer.get_tier(Path("deploy.sh")) == 3
    assert prioritizer.get_tier(Path("README.md")) == 3
    assert prioritizer.get_tier(Path("locales/es.json")) == 3


def test_tier2_boosting_order() -> None:
    prioritizer = RiskPrioritizer()
    candidates = [
        Path("helpers.py"),
        Path("utils.py"),
        Path("auth_service.py"),  # Boost priority 0
        Path("api_routes.py"),    # Boost priority 0
        Path("server.py"),        # Boost priority 1 (entrypoint)
    ]
    res = prioritizer.prioritize(candidates, max_allocation=3)
    top_names = [f.name for f in res.files]
    assert "auth_service.py" in top_names
    assert "api_routes.py" in top_names
    assert "server.py" in top_names


def test_quota_allocation_and_backfilling() -> None:
    prioritizer = RiskPrioritizer()

    # 30 Tier 1, 30 Tier 2, 10 Tier 3 -> capped to 50 (25 / 20 / 5)
    t1_files = [Path(f"secret_{i}.env") for i in range(30)]
    t2_files = [Path(f"code_{i}.py") for i in range(30)]
    t3_files = [Path(f"doc_{i}.md") for i in range(10)]

    res50 = prioritizer.prioritize(t1_files + t2_files + t3_files, max_allocation=50)
    assert len(res50.files) == 50
    assert res50.tier1_count == 25
    assert res50.tier2_count == 20
    assert res50.tier3_count == 5

    # Backfilling test: only 5 Tier 1, but 40 Tier 2, 2 Tier 3 -> all 47 fit in 50
    few_t1 = [Path(f"secret_{i}.env") for i in range(5)]
    many_t2 = [Path(f"code_{i}.py") for i in range(40)]
    few_t3 = [Path(f"doc_{i}.md") for i in range(2)]

    res_backfill = prioritizer.prioritize(few_t1 + many_t2 + few_t3, max_allocation=50)
    assert len(res_backfill.files) == 47
    assert res_backfill.tier1_count == 5
    assert res_backfill.tier2_count == 40
    assert res_backfill.tier3_count == 2


def test_prioritization_result_tuple_compatibility() -> None:
    prioritizer = RiskPrioritizer()
    files = [Path("a.env"), Path("b.py"), Path("c.md")]
    res = prioritizer.prioritize(files, max_allocation=10)

    # Test unpacking
    unpacked_files, t1, t2 = res
    assert len(unpacked_files) == 3
    assert t1 == 1
    assert t2 == 1

    # Test properties
    assert isinstance(res, PrioritizationResult)
    assert res.tier3_count == 1
