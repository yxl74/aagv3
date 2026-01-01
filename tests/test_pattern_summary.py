from __future__ import annotations

from apk_analyzer.phase0.pattern_summary import build_cooccurrence_pattern_summary


def test_app_level_union_matches_cross_class_patterns() -> None:
    component_entry = (
        "<com.samsung.android.messaging.MaliciousFunctionsService: "
        "int onStartCommand(android.content.Intent,int,int)>"
    )
    callback_entry = "<com.samsung.android.messaging.CommandRunner: void run()>"
    groups = [
        {
            "group_id": "grp-1",
            "caller_class": "com.samsung.android.messaging.MaliciousFunctions",
            "caller_method": "<com.samsung.android.messaging.MaliciousFunctions: void doStuff()>",
            "categories": [
                "SYSTEM_MANIPULATION_PACKAGE",
                "INPUT_PROMPT_OVERLAY",
                "SURVEILLANCE_AUDIO",
                "COLLECTION_CONTACTS",
                "COLLECTION_SMS_MESSAGES",
            ],
            "string_categories": [],
            "reachability": {
                "reachable_from_entrypoint": True,
                "shortest_path_len": 2,
                "example_path": [
                    callback_entry,
                    "<com.samsung.android.messaging.MaliciousFunctions: void doStuff()>",
                ],
            },
        },
        {
            "group_id": "grp-2",
            "caller_class": "com.samsung.android.messaging.MaliciousAccessibility",
            "caller_method": "<com.samsung.android.messaging.MaliciousAccessibility: void onEvent()>",
            "categories": ["ABUSE_ACCESSIBILITY"],
            "string_categories": [],
            "reachability": {
                "reachable_from_entrypoint": True,
                "shortest_path_len": 3,
                "example_path": [
                    callback_entry,
                    "<com.samsung.android.messaging.MaliciousAccessibility: void onEvent()>",
                ],
            },
        },
        {
            "group_id": "grp-3",
            "caller_class": "com.samsung.android.messaging.ScreenCaptureService",
            "caller_method": "<com.samsung.android.messaging.ScreenCaptureService: void capture()>",
            "categories": ["SURVEILLANCE_SCREEN_CAPTURE"],
            "string_categories": [],
            "reachability": {
                "reachable_from_entrypoint": True,
                "shortest_path_len": 3,
                "example_path": [
                    callback_entry,
                    "<com.samsung.android.messaging.ScreenCaptureService: void capture()>",
                ],
            },
        },
        {
            "group_id": "grp-4",
            "caller_class": "com.samsung.android.messaging.TcpC2Communicator",
            "caller_method": "<com.samsung.android.messaging.TcpC2Communicator: void run()>",
            "categories": ["C2_NETWORKING"],
            "string_categories": [],
            "reachability": {
                "reachable_from_entrypoint": True,
                "shortest_path_len": 2,
                "example_path": [
                    callback_entry,
                    "<com.samsung.android.messaging.TcpC2Communicator: void run()>",
                ],
            },
        },
        {
            "group_id": "grp-5",
            "caller_class": "com.samsung.android.messaging.PermissionsActivity",
            "caller_method": "<com.samsung.android.messaging.PermissionsActivity: void onCreate()>",
            "categories": [],
            "string_categories": ["SOCIAL_ENGINEERING_PERMISSION_LURE_SETTINGS"],
            "reachability": {
                "reachable_from_entrypoint": True,
                "shortest_path_len": 1,
                "example_path": [
                    callback_entry,
                    "<com.samsung.android.messaging.PermissionsActivity: void onCreate()>",
                ],
            },
        },
    ]

    callgraph = {
        "nodes": [
            {
                "method": component_entry,
                "class": "com.samsung.android.messaging.MaliciousFunctionsService",
            },
            {
                "method": callback_entry,
                "class": "com.samsung.android.messaging.CommandRunner",
            },
            {
                "method": "<com.samsung.android.messaging.MaliciousFunctions: void doStuff()>",
                "class": "com.samsung.android.messaging.MaliciousFunctions",
            },
            {
                "method": "<com.samsung.android.messaging.MaliciousAccessibility: void onEvent()>",
                "class": "com.samsung.android.messaging.MaliciousAccessibility",
            },
            {
                "method": "<com.samsung.android.messaging.ScreenCaptureService: void capture()>",
                "class": "com.samsung.android.messaging.ScreenCaptureService",
            },
            {
                "method": "<com.samsung.android.messaging.TcpC2Communicator: void run()>",
                "class": "com.samsung.android.messaging.TcpC2Communicator",
            },
            {
                "method": "<com.samsung.android.messaging.PermissionsActivity: void onCreate()>",
                "class": "com.samsung.android.messaging.PermissionsActivity",
            },
        ],
        "edges": [
            {"caller": component_entry, "callee": callback_entry},
            {
                "caller": callback_entry,
                "callee": "<com.samsung.android.messaging.MaliciousFunctions: void doStuff()>",
            },
            {
                "caller": callback_entry,
                "callee": "<com.samsung.android.messaging.MaliciousAccessibility: void onEvent()>",
            },
            {
                "caller": callback_entry,
                "callee": "<com.samsung.android.messaging.ScreenCaptureService: void capture()>",
            },
            {
                "caller": callback_entry,
                "callee": "<com.samsung.android.messaging.TcpC2Communicator: void run()>",
            },
            {
                "caller": callback_entry,
                "callee": "<com.samsung.android.messaging.PermissionsActivity: void onCreate()>",
            },
        ],
        "metadata": {},
    }
    manifest = {
        "package_name": "com.samsung.android.messaging",
        "services": ["com.samsung.android.messaging.MaliciousFunctionsService"],
    }

    summary = build_cooccurrence_pattern_summary(
        groups,
        [],
        callgraph=callgraph,
        manifest=manifest,
    )

    expected = [
        "P_DROP_INSTALL_VIA_NET",
        "P_DROP_INSTALL_SETTINGS_LURE",
        "P_DROP_TO_ACCESSIBILITY",
        "P_ODF_REMOTE_STREAM",
        "P_ODF_OVERLAY_OR_WEBINJECT",
        "P_STALKERWARE_COLLECTION_BUNDLE",
    ]
    assert summary["app_level"]["from_all_groups"]["patterns_matched"] == expected
    assert summary["app_level"]["from_reachable_groups"]["patterns_matched"] == expected

    entrypoints = summary["entrypoint_level"]["from_reachable_groups"]["entrypoints"]
    assert len(entrypoints) == 1
    assert entrypoints[0]["entrypoint"] == component_entry
    assert entrypoints[0]["patterns_matched"] == expected

    packages = summary["package_level"]["from_all_groups"]
    assert len(packages) == 1
    assert packages[0]["package"] == "com.samsung.android.messaging"
    assert packages[0]["patterns_matched"] == expected
