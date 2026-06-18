import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

const jbMono = JetBrains_Mono({ subsets: ["latin"] });

export const metadata = {
  title: "SecureX — AI-Powered Malware Forensics",
  description:
    "Upload an APK. Get back a technical forensic intelligence report powered by GenAI — in under 8 minutes.",
  keywords: "APK analysis, malware detection, forensics, GenAI, threat intelligence",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className={jbMono.className}>{children}</body>
    </html>
  );
}
