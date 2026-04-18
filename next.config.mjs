/** @type {import('next').NextConfig} */
const nextConfig = {
  devIndicators: {
    appIsrStatus: false,
    buildActivity: false,
    buildActivityPosition: 'bottom-right',
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  allowedDevOrigins: ["*.replit.dev", "*.replit.app", "*.janeway.replit.dev"],
  async rewrites() {
    // Backend Flask API runs on port 8000; Next.js frontend on port 5000
    const target = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    return [
      { source: '/api/:path*', destination: `${target}/api/:path*` },
      { source: '/socket.io/:path*', destination: `${target}/socket.io/:path*` },
    ];
  },
}

export default nextConfig
