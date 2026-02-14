import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'LifePilot Dashboard',
  description: 'Manage your life with AI',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="bg-gray-50">{children}</body>
    </html>
  )
}
