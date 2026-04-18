class RiskEngine:
    def __init__(self, trusted_aps=None):
        if trusted_aps is None:
            from sensor.config import TRUSTED_APS

            self.trusted_aps = TRUSTED_APS
        else:
            self.trusted_aps = trusted_aps

    def analyze(self, event):
        score = 0
        reasons = []

        ssid = event.get("ssid")
        bssid = event.get("bssid")
        channel = event.get("channel")
        signal = event.get("signal")
        encryption = event.get("encryption")
        clients = event.get("clients", 0)

        if encryption == "OPEN" and clients > 0:
            score += 5
            reasons.append("Open network with connected clients")

        if ssid in self.trusted_aps:
            trusted = self.trusted_aps[ssid]
            trusted_bssid = str(trusted.get("bssid") or "").lower()
            if trusted_bssid and bssid and bssid.lower() != trusted_bssid:
                score += 6
                reasons.append("Evil twin suspected (BSSID mismatch)")
            else:
                trusted_enc = trusted.get("encryption", "SECURED")
                if encryption != trusted_enc:
                    score += 6
                    reasons.append(f"Encryption downgrade (expected {trusted_enc}, got {encryption})")

            trusted_channel = trusted.get("channel")
            if trusted_channel and channel != trusted_channel:
                score += 2
                reasons.append("Channel mismatch")
        else:
            score += 3
            reasons.append("SSID not in trusted baseline")

        if signal is not None and signal > -30:
            score += 2
            reasons.append("Unusually strong signal")

        classification = self.classify(score)
        return {
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

    @staticmethod
    def classify(score):
        if score >= 6:
            return "ROGUE"
        if score >= 3:
            return "SUSPICIOUS"
        return "LEGIT"
