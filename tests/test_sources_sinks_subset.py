from pathlib import Path

from apk_analyzer.analyzers.sources_sinks_subset import generate_subset


def test_generate_subset(tmp_path: Path):
    base = tmp_path / "SourcesAndSinks.txt"
    base.write_text(
        "<android.telephony.TelephonyManager: java.lang.String getDeviceId()> -> _SOURCE_\n"
        "<java.net.URL: java.net.URLConnection openConnection()> -> _SINK_\n",
        encoding="utf-8",
    )
    output = tmp_path / "subset.txt"
    generate_subset(base, output, ["SENSITIVE_DATA_ACCESS"], taint_question=None)
    content = output.read_text(encoding="utf-8")
    assert "TelephonyManager" in content
