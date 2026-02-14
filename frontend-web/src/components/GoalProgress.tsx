export default function GoalProgress() {
  const goals = [
    { id: 1, title: 'Read 2 books', progress: 50, color: 'bg-green-500' },
    { id: 2, title: 'Daily Meditation', progress: 80, color: 'bg-purple-500' },
  ]

  return (
    <div className="space-y-6">
      {goals.map(goal => (
        <div key={goal.id}>
          <div className="flex justify-between mb-1">
            <span className="font-medium">{goal.title}</span>
            <span className="text-sm text-gray-600">{goal.progress}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div className={`${goal.color} h-2 rounded-full`} style={{ width: `${goal.progress}%` }}></div>
          </div>
        </div>
      ))}
    </div>
  )
}
