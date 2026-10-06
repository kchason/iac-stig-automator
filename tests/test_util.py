from stig_automator.util import first_nested, get_nested


class TestGetNested:
    def test_simple_key(self):
        assert get_nested({"a": 1}, "a") == 1

    def test_nested_keys(self):
        assert get_nested({"a": {"b": {"c": 3}}}, "a", "b", "c") == 3

    def test_missing_key_returns_default(self):
        assert get_nested({"a": 1}, "b") is None
        assert get_nested({"a": 1}, "b", default="x") == "x"

    def test_list_index(self):
        assert get_nested({"a": [10, 20, 30]}, "a", 1) == 20

    def test_list_index_out_of_range(self):
        assert get_nested({"a": [10]}, "a", 5, default="x") == "x"

    def test_none_intermediate(self):
        assert get_nested({"a": None}, "a", "b", default="x") == "x"

    def test_non_dict_non_list(self):
        assert get_nested({"a": 42}, "a", "b", default="x") == "x"

    def test_empty_dict(self):
        assert get_nested({}, "a", default="x") == "x"

    def test_returns_default_for_none_value(self):
        assert get_nested({"a": None}, "a", default="fallback") == "fallback"


class TestFirstNested:
    def test_first_element(self):
        assert first_nested({"a": [1, 2, 3]}, "a") == 1

    def test_empty_list(self):
        assert first_nested({"a": []}, "a") is None
        assert first_nested({"a": []}, "a", default="x") == "x"

    def test_missing_key(self):
        assert first_nested({}, "a", default="x") == "x"

    def test_nested(self):
        data = {"a": {"b": [{"c": 1}, {"c": 2}]}}
        assert first_nested(data, "a", "b") == {"c": 1}

    def test_non_list(self):
        assert first_nested({"a": "string"}, "a", default="x") == "x"
