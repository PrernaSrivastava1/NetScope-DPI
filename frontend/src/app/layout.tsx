import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "NetScope-DPI — Deep Packet Inspection",
  description:
    "Upload a .pcap network capture file and instantly visualize every connection, application, and packet in your browser. No Wireshark needed.",
  keywords: [
    "deep packet inspection",
    "network analysis",
    "pcap",
    "traffic visualizer",
    "wireshark alternative",
    "java",
    "nextjs",
  ],
  authors: [{ name: "Prerna Srivastava", url: "https://github.com/PrernaSrivastava1" }],
  icons: {
    icon: "/favicon.png",
    apple: "/icon.png",
  },
  openGraph: {
    title: "NetScope-DPI — Deep Packet Inspection",
    description:
      "Upload a .pcap file and instantly see every connection, app, and packet — visualized in your browser.",
    url: "https://frontend-tan-eta-66.vercel.app",
    siteName: "NetScope-DPI",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "NetScope-DPI — Deep Packet Inspection",
    description:
      "Upload a .pcap file and instantly see every connection, app, and packet — visualized in your browser.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
