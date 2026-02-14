from typing import List, Dict

class GoalTracker:
    def __init__(self):
        self.goals = {}

    def update_goal_progress(self, user_id: str, goal_id: str, progress: float):
        if user_id not in self.goals:
            self.goals[user_id] = {}
        self.goals[user_id][goal_id] = progress
        return {"goal_id": goal_id, "new_progress": progress}

    def get_user_goals(self, user_id: str):
        return self.goals.get(user_id, {})
