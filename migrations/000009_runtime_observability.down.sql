DROP TRIGGER IF EXISTS otlp_config_tests_append_only ON otlp_config_tests;
DROP TRIGGER IF EXISTS otlp_config_versions_append_only ON otlp_config_versions;
DROP FUNCTION IF EXISTS protect_otlp_config_test_history();
DROP FUNCTION IF EXISTS protect_otlp_config_version_history();
DROP TABLE IF EXISTS otlp_runtime_state;
DROP TABLE IF EXISTS otlp_config_tests;
DROP TABLE IF EXISTS otlp_config_versions;
