export const metadata = { title: "EDF Agent", description: "Export Declaration Form agent for Indian service exporters" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
