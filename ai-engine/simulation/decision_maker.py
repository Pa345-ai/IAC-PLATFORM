from typing import Dict, Any, List
import random

class DecisionMaker:
    def __init__(self, llm_client=None):
        self.llm_client = llm_client

    def decide(self, user_context: Dict[str, Any], goal_state: Dict[str, Any], available_actions: List[str]):
        """
        Uses a combination of rules and LLM to decide on the next best action.
        """
        # Rule-based filtering
        if user_context.get('energy_level') == 'low':
            if "suggest_rest" in available_actions:
                return {"action": "suggest_rest", "reason": "User energy is low"}

        # Mock LLM decision logic
        if available_actions:
            decision = random.choice(available_actions)
        else:
            decision = "no_action"

        return {
            "action": decision,
            "reason": "Optimal action based on current goals and context",
            "confidence": 0.9
        }
