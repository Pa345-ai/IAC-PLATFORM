import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from planners.optimizer import ScheduleOptimizer

def test_optimizer_no_conflicts():
    optimizer = ScheduleOptimizer()
    events = [
        {'id': 1, 'start_time': '2026-01-01T09:00:00Z', 'end_time': '2026-01-01T10:00:00Z'},
        {'id': 2, 'start_time': '2026-01-01T11:00:00Z', 'end_time': '2026-01-01T12:00:00Z'}
    ]
    result = optimizer.optimize(events, [])
    assert result['conflicts_resolved'] == 0
    print("AI Engine Test Passed: Optimizer correctly identified no conflicts.")

if __name__ == "__main__":
    test_optimizer_no_conflicts()
