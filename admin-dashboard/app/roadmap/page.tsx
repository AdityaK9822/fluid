import type { Metadata } from "next";
import { getPortalLinks } from "@/lib/portal-links";
import { RoadmapBoard } from "@/components/developer-portal/RoadmapBoard";

export async function generateMetadata(): Promise<Metadata> {
  const { siteUrl } = getPortalLinks();
  const title = "Fluid Public Roadmap";
  const description =
    "Vote on upcoming Fluid features and track progress from Planned to Shipped. Community votes shape our sprint priorities.";

  return {
    title,
    description,
    keywords: [
      "Fluid",
      "roadmap",
      "feature requests",
      "voting",
      "Stellar",
      "planned",
      "shipped",
    ],
    metadataBase: new URL(siteUrl),
    alternates: { canonical: "/roadmap" },
    openGraph: {
      title,
      description,
      url: `${siteUrl}/roadmap`,
      siteName: "Fluid",
      type: "website",
    },
    twitter: { card: "summary_large_image", title, description },
    robots: { index: true, follow: true },
  };
}

export default function RoadmapPage() {
  return <RoadmapBoard />;
}
