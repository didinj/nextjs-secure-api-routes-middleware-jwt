import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import jwt from "jsonwebtoken";

export function middleware(req: NextRequest) {
    const { pathname } = req.nextUrl;

    // Allow access to login route without a token
    if (pathname.startsWith("/api/auth/login")) {
        return NextResponse.next();
    }

    // Get token from Authorization header or cookies
    const authHeader = req.headers.get("authorization");
    const token = authHeader?.split(" ")[1];

    if (!token) {
        return NextResponse.json({ message: "Missing token" }, { status: 401 });
    }

    try {
        // Verify the token
        jwt.verify(token, process.env.JWT_SECRET as string);
        return NextResponse.next();
    } catch (err) {
        return NextResponse.json({ message: "Invalid or expired token" }, { status: 403 });
    }
}

export const config = {
    matcher: ["/api/user/:path*"],
};
