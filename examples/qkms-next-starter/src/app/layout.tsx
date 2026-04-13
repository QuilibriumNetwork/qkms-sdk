import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { Providers } from '@/providers/providers';

export const metadata: Metadata = {
  title: 'qkms-sdk Next.js starter',
  description: 'QKMS SDK starter (Next.js 15 App Router).',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        style={{
          fontFamily: 'system-ui, -apple-system, sans-serif',
          margin: 0,
          padding: 0,
          background: '#f7f8fa',
          color: '#111',
        }}
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
