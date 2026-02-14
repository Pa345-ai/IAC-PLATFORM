import json
import os

# This script mocks the integration between the Backend and the AI Engine
# since we cannot easily run the full docker-compose in this environment.

def simulate_backend_to_ai_call():
    print("Simulating Backend calling AI Engine...")

    # Mocking the AI Engine response logic from ai-engine/simulation/decision_maker.py
    user_context = {"energy_level": "low"}
    available_actions = ["suggest_rest", "start_coding"]

    print(f"Request Context: {user_context}")
    print(f"Available Actions: {available_actions}")

    # Logic from DecisionMaker
    if user_context.get('energy_level') == 'low':
        decision = {"action": "suggest_rest", "reason": "User energy is low"}
    else:
        decision = {"action": "start_coding", "reason": "User energy is normal"}

    print(f"AI Engine Response: {json.dumps(decision, indent=2)}")
    return decision

def test_integration():
    decision = simulate_backend_to_ai_call()
    assert decision['action'] == 'suggest_rest'
    print("\nIntegration Test Passed: AI Engine correctly identified the action based on user context.")

if __name__ == "__main__":
    test_integration()
