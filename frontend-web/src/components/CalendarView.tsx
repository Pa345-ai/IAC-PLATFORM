export default function CalendarView() {
  const events = [
    { id: 1, title: 'Deep Work Session', time: '9:00 AM - 11:00 AM', category: 'Work' },
    { id: 2, title: 'Lunch with Team', time: '12:00 PM - 1:00 PM', category: 'Social' },
    { id: 3, title: 'Gym', time: '5:30 PM - 6:30 PM', category: 'Health' },
  ]

  return (
    <div className="space-y-4">
      {events.map(event => (
        <div key={event.id} className="p-3 bg-blue-50 border-l-4 border-blue-500 rounded">
          <div className="font-medium">{event.title}</div>
          <div className="text-sm text-gray-600">{event.time}</div>
        </div>
      ))}
    </div>
  )
}
