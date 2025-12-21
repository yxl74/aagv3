from apk_analyzer.utils.signature_normalize import dex_method_to_soot, normalize_signature


def test_dex_method_to_soot():
    sig = dex_method_to_soot("Landroid/telephony/TelephonyManager;", "getDeviceId", "()Ljava/lang/String;")
    assert sig == "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>"


def test_normalize_signature_dex():
    sig = normalize_signature("Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;")
    assert sig == "<android.telephony.TelephonyManager: java.lang.String getDeviceId()>"
