import CalendarView from '../components/CalendarView'
import GoalProgress from '../components/GoalProgress'

export default function Home() {
  return (
    <main className="min-h-screen p-8">
      <header className="mb-8">
        <h1 className="text-3xl font-bold">LifePilot Dashboard</h1>
        <p className="text-gray-600">Welcome back, Jules. Your AI is active.</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <section className="bg-white p-6 rounded-xl shadow-sm border">
          <h2 className="text-xl font-semibold mb-4">Your Schedule</h2>
          <CalendarView />
        </section>

        <section className="bg-white p-6 rounded-xl shadow-sm border">
          <h2 className="text-xl font-semibold mb-4">Goal Progress</h2>
          <GoalProgress />
        </section>
      </div>
    </main>
  )
}
