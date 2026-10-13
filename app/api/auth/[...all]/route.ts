import { withAuth } from "@/src/auth/auth";

export const dynamic = "force-dynamic";

const handle = (request: Request) => withAuth((auth) => auth.handler(request));

export { handle as GET, handle as POST };
