# detection/risk_engine.py

class RiskEngine:
    def __init__(self, trusted_aps=None):
        # لو مفيش قايمة جاية من الـ API، هيسحب اللي في الـ config كاحتياطي
        if trusted_aps is None:
            from config import TRUSTED_APS
            self.trusted_aps = TRUSTED_APS
        else:
            self.trusted_aps = trusted_aps

    def analyze(self, event):
        """
        يحلل event ويحسب درجة الخطورة.
        """
        score = 0
        reasons = []

        ssid = event.get("ssid")
        bssid = event.get("bssid")
        channel = event.get("channel")
        signal = event.get("signal")
        encryption = event.get("encryption")
        clients = event.get("clients", 0)

        # 🔹 Open network مع عملاء متصلين
        if encryption == "OPEN" and clients > 0:
            score += 5
            reasons.append("Open network with connected clients")

        # 🔹 الشبكة معروفة / trusted
        if ssid in self.trusted_aps:
            trusted = self.trusted_aps[ssid]

            # Evil Twin (SSID مطابق لكن BSSID مختلف)
            if bssid.lower() != trusted["bssid"].lower():
                score += 6
                reasons.append("Evil Twin suspected (BSSID Spoofing)")
            else:
                # 🚀 التعديل الأمني: لو المهاجم قلد الـ MAC بس غير التشفير لـ OPEN
                trusted_enc = trusted.get("encryption", "SECURED")
                if encryption != trusted_enc:
                    score += 6
                    reasons.append(f"Encryption downgrade (Expected {trusted_enc}, got {encryption})")

            # Channel mismatch
            if channel != trusted["channel"]:
                score += 2
                reasons.append("Channel mismatch")

        # 🔹 SSID غير معروف
        else:
            score += 3
            reasons.append("SSID not trusted")

        # 🔹 إشارة قوية بشكل غير طبيعي
        if signal is not None and signal > -30:
            score += 2
            reasons.append("Unusually strong signal")

        classification = self.classify(score)

        event_summary = {
            "classification": classification,
            "score": score,
            "reasons": reasons,
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel,
            "signal": signal,
            "encryption": encryption,
            "clients": clients,
            "manufacturer": event.get("manufacturer", "Unknown"),
            "uptime": event.get("uptime", ""),
            "auth": event.get("auth", ""),
            "wps": event.get("wps", ""),
            "distance": event.get("distance", -1),
            "raw_beacon": event.get("raw_beacon", ""),
        }

        return event_summary

    def classify(self, score):
        if score >= 6:
            return "ROGUE"
        elif score >= 3:
            return "SUSPICIOUS"
        return "LEGIT"
