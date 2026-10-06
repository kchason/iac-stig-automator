from stig_automator.registry import detect_modules, get_all_modules, get_module, registered_names

import stig_automator.modules  # noqa: F401


class TestRegistry:
    def test_aks_registered(self):
        assert "aks" in registered_names()

    def test_mysql_flexible_registered(self):
        assert "mysql_flexible" in registered_names()

    def test_postgres_flexible_registered(self):
        assert "postgres_flexible" in registered_names()

    def test_aws_modules_registered(self):
        assert "eks" in registered_names()
        assert "rds_mysql" in registered_names()
        assert "rds_postgres" in registered_names()
        assert "azure_sql_database" in registered_names()
        assert "azure_sql_managed_instance" in registered_names()

    def test_get_module(self):
        mod = get_module("aks")
        assert mod.name == "aks"
        assert mod.resource_type == "azurerm_kubernetes_cluster"

    def test_get_all_modules(self):
        modules = get_all_modules()
        names = {m.name for m in modules}
        assert "aks" in names
        assert "mysql_flexible" in names
        assert "postgres_flexible" in names
        assert "eks" in names
        assert "rds_mysql" in names
        assert "rds_postgres" in names
        assert "azure_sql_database" in names
        assert "azure_sql_managed_instance" in names

    def test_detect_modules_aks(self):
        modules = detect_modules({"azurerm_kubernetes_cluster", "azurerm_resource_group"})
        names = {m.name for m in modules}
        assert "aks" in names
        assert "mysql_flexible" not in names
        assert "postgres_flexible" not in names

    def test_detect_modules_both(self):
        modules = detect_modules({
            "azurerm_kubernetes_cluster",
            "azurerm_mysql_flexible_server",
            "azurerm_postgresql_flexible_server",
        })
        names = {m.name for m in modules}
        assert "aks" in names
        assert "mysql_flexible" in names
        assert "postgres_flexible" in names

    def test_detect_modules_aws(self):
        modules = detect_modules({
            "aws_db_instance",
            "aws_eks_cluster",
            "aws_eks_node_group",
        })
        names = {m.name for m in modules}
        assert "eks" in names
        assert "rds_mysql" in names
        assert "rds_postgres" in names

    def test_detect_modules_aurora_clusters(self):
        modules = detect_modules({"aws_rds_cluster"})
        names = {m.name for m in modules}
        assert "rds_mysql" in names
        assert "rds_postgres" in names
        assert "eks" not in names

    def test_detect_modules_azure_sql_database(self):
        modules = detect_modules({"azurerm_mssql_server", "azurerm_resource_group"})
        names = {m.name for m in modules}
        assert "azure_sql_database" in names
        assert "aks" not in names

    def test_detect_modules_azure_sql_managed_instance(self):
        modules = detect_modules({"azurerm_mssql_managed_instance", "azurerm_resource_group"})
        names = {m.name for m in modules}
        assert "azure_sql_managed_instance" in names
        assert "azure_sql_database" not in names

    def test_detect_modules_none(self):
        assert detect_modules({"aws_instance"}) == []

    def test_module_metadata(self):
        mod = get_module("mysql_flexible")
        assert mod.resource_type == "azurerm_mysql_flexible_server"
        assert "azurerm_mysql_flexible_server_configuration" in mod.related_resource_types
        assert mod.report_title == "MySQL Flexible Server STIG Report"
        postgres = get_module("postgres_flexible")
        assert postgres.resource_type == "azurerm_postgresql_flexible_server"
        assert "azurerm_postgresql_flexible_server_configuration" in postgres.related_resource_types
        assert postgres.report_title == "Azure PostgreSQL Flexible Server STIG Report"

    def test_controls_not_empty(self):
        for mod in get_all_modules():
            assert len(mod.controls()) > 0, f"Module {mod.name} has no controls"

    def test_stig_benchmark_metadata(self):
        for mod in get_all_modules():
            assert mod.stig_benchmark_id, f"Module {mod.name} has no stig_benchmark_id"
            assert mod.stig_benchmark_title, f"Module {mod.name} has no stig_benchmark_title"
