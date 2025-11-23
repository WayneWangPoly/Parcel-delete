import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MicroExpress Admin Portal",
  description: "MicroExpress internal admin portal for drivers and operations.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-50">
        {children}
      </body>
    </html>
  );
}
