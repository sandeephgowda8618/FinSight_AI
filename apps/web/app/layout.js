export const metadata = {
  title: "FinSight AI",
  description: "Financial research and analytics workspace",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
