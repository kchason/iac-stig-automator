from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def aks_plan() -> dict:
    return json.loads((FIXTURES_DIR / "aks_sample_plan.json").read_text())


@pytest.fixture
def mysql_plan() -> dict:
    return json.loads((FIXTURES_DIR / "mysql_sample_plan.json").read_text())


@pytest.fixture
def postgres_plan() -> dict:
    return json.loads((FIXTURES_DIR / "postgres_sample_plan.json").read_text())


@pytest.fixture
def rds_mysql_plan() -> dict:
    return json.loads((FIXTURES_DIR / "rds_mysql_sample_plan.json").read_text())


@pytest.fixture
def rds_postgres_plan() -> dict:
    return json.loads((FIXTURES_DIR / "rds_postgres_sample_plan.json").read_text())


@pytest.fixture
def eks_plan() -> dict:
    return json.loads((FIXTURES_DIR / "eks_sample_plan.json").read_text())


@pytest.fixture
def azure_sql_database_plan() -> dict:
    return json.loads((FIXTURES_DIR / "azure_sql_database_sample_plan.json").read_text())


@pytest.fixture
def azure_sql_managed_instance_plan() -> dict:
    return json.loads((FIXTURES_DIR / "azure_sql_managed_instance_sample_plan.json").read_text())
