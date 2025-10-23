import { NextResponse } from "next/server";
import jwt from "jsonwebtoken";

export async function GET(request: Request) {
    try {
        // Extract the Authorization header
        const authHeader = request.headers.get("authorization");
        const token = authHeader?.split(" ")[1];

        if (!token) {
            return NextResponse.json({ message: "Token is missing" }, { status: 401 });
        }

        // Verify and decode the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string);

        // Example: return some user data
        return NextResponse.json({
            message: "Access granted to protected route!",
            user: decoded,
        });
    } catch (error) {
        console.error("Error verifying token:", error);
        return NextResponse.json({ message: "Invalid or expired token" }, { status: 403 });
    }
}
