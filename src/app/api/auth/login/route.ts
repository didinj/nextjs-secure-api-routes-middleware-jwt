import { NextResponse } from "next/server";
import jwt, { SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";

const user = {
    id: 1,
    username: "admin",
    password:
        "$2a$10$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36x.4Y2YlW3K9fIx0D9eH2a", // 'password123' hashed
};

export async function POST(request: Request) {
    try {
        const { username, password } = await request.json();

        // Validate username
        if (username !== user.username) {
            return NextResponse.json({ message: "Invalid username" }, { status: 401 });
        }

        // Compare password
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return NextResponse.json({ message: "Invalid password" }, { status: 401 });
        }

        // Ensure JWT secret exists
        const secret = process.env.JWT_SECRET;
        if (!secret) {
            throw new Error("JWT_SECRET is not defined in environment variables");
        }

        // Resolve expiresIn: if it's a pure number string, convert to number.
        const rawExpires = process.env.JWT_EXPIRES_IN ?? "1h";
        let expiresInValue: number | string;

        // if the env var is like "3600" (only digits), pass number; otherwise pass string like "1h"
        if (/^\d+$/.test(rawExpires)) {
            expiresInValue = Number(rawExpires);
        } else {
            expiresInValue = rawExpires;
        }

        // Cast through unknown to match internal StringValue union that isn't exported.
        const options: SignOptions = {
            expiresIn: expiresInValue as unknown as SignOptions["expiresIn"],
        };

        const payload = { id: user.id, username: user.username };
        const token = jwt.sign(payload, secret, options);

        return NextResponse.json({ token }, { status: 200 });
    } catch (error) {
        console.error("Login error:", error);
        return NextResponse.json({ message: "Internal server error" }, { status: 500 });
    }
}
