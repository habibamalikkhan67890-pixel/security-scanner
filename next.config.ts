import type { NextConfig } from "next";

// FastAPI backend ka address. Browser sirf Next.js (port 3000) se baat karta hai;
// /api/* requests yahan se FastAPI ko forward hoti hain (same-origin => cookies aur CSRF sahi chalte hain).
const backend = (process.env.BACKEND_URL ?? "http://127.0.0.1:5000").replace(/\/$/, "");

const config: NextConfig = {
  reactStrictMode: true,
  // http://127.0.0.1:3000 se kholne par bhi dev server (HMR) block na ho
  allowedDevOrigins: ["127.0.0.1"],
  poweredByHeader: false,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          // Next.js hydration inline scripts use karta hai, isliye script-src yahan strict nahi rakha.
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'" },
        ],
      },
    ];
  },
};

export default config;
