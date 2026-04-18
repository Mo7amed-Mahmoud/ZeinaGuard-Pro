import { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Network Map - ZeinaGuard',
  description: 'Real-time network topology visualization',
};

export default function TopologyLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
