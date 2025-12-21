from apk_analyzer.analyzers.consistency_checker import consistency_check


def test_consistency_checker_pass():
    tier1 = {
        "facts": [{"fact": "Calls getDeviceId", "support_unit_ids": ["u1"]}],
    }
    context = {
        "sliced_cfg": {"units": [{"unit_id": "u1", "stmt": "r0 = virtualinvoke r1.getDeviceId()"}]},
        "static_context": {"strings_nearby": []},
    }
    result = consistency_check(tier1, context)
    assert result["ok"]


def test_consistency_checker_missing_unit():
    tier1 = {
        "facts": [{"fact": "Calls getDeviceId", "support_unit_ids": ["u2"]}],
    }
    context = {
        "sliced_cfg": {"units": [{"unit_id": "u1", "stmt": "r0 = virtualinvoke r1.getDeviceId()"}]},
        "static_context": {"strings_nearby": []},
    }
    result = consistency_check(tier1, context)
    assert not result["ok"]
    assert "u2" in result["missing_unit_ids"]
