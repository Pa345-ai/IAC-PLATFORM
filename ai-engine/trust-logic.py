from typing import Dict

class TrustEscalator:
    def __init__(self):
        self.levels = ["ASK", "SUGGEST", "NOTIFY", "AUTO"]

    def calculate_trust_level(self, success_count: int, failure_count: int):
        """
        Calculates the current trust level based on historical performance.
        """
        score = success_count - (failure_count * 2)
        if score < 5:
            return "ASK"
        elif score < 15:
            return "SUGGEST"
        elif score < 30:
            return "NOTIFY"
        else:
            return "AUTO"

    def get_action_mode(self, trust_level: str):
        """
        Returns how an action should be handled based on trust level.
        """
        return {
            "ASK": "request_permission",
            "SUGGEST": "propose_and_wait",
            "NOTIFY": "execute_and_notify",
            "AUTO": "silent_execution"
        }.get(trust_level, "request_permission")
