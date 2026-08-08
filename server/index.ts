import { Database } from "bun:sqlite";
import { createHmac, timingSafeEqual } from "node:crypto";
import { dirname } from "node:path";
import { mkdirSync } from "node:fs";

const PORT = Number(Bun.env.PORT || 8080);
const DB_PATH = Bun.env.DB_PATH || "/app/data/commercial.db";
const JWT_SECRET = Bun.env.JWT_SECRET || "";
const ADMIN_USERNAME = Bun.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = Bun.env.ADMIN_PASSWORD || "";
const INITIAL_CREDITS = Number(Bun.env.INITIAL_CREDITS || 100);

if (JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET 必须至少 32 位");
}

mkdirSync(dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH, { create: true });

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    credits INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

type TokenPayload = {
  sub: number;
  username: string;
  role: string;
  exp: number;
};

function json(data: unknown, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
    },
  });
}

function signToken(payload: TokenPayload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");

  const signature = createHmac("sha256", JWT_SECRET)
    .update(body)
    .digest("base64url");

  return `${body}.${signature}`;
}

function verifyToken(token: string): TokenPayload | null {
  try {
    const [body, signature] = token.split(".");

    if (!body || !signature) return null;

    const expected = createHmac("sha256", JWT_SECRET)
      .update(body)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8"),
    ) as TokenPayload;

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getCurrentUser(req: Request) {
  const auth = req.headers.get("authorization");

  if (!auth?.startsWith("Bearer ")) {
    return null;
  }

  const payload = verifyToken(auth.slice(7));

  if (!payload) return null;

  return db
    .query(
      "SELECT id, username, role, credits, created_at FROM users WHERE id = ?",
    )
    .get(payload.sub);
}

function createLoginToken(user: any) {
  return signToken({
    sub: user.id,
    username: user.username,
    role: user.role,
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
  });
}

// 第一次启动自动创建管理员。
// 已经存在后不会重复覆盖密码。
const existingAdmin = db
  .query("SELECT id FROM users WHERE username = ?")
  .get(ADMIN_USERNAME);

if (!existingAdmin && ADMIN_PASSWORD) {
  const hash = await Bun.password.hash(ADMIN_PASSWORD);

  db.query(`
    INSERT INTO users (username, password_hash, role, credits)
    VALUES (?, ?, 'admin', 0)
  `).run(ADMIN_USERNAME, hash);

  console.log(`管理员 ${ADMIN_USERNAME} 创建成功`);
}

Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,

  async fetch(req) {
    const url = new URL(req.url);

    // 健康检查
    if (req.method === "GET" && url.pathname === "/api/health") {
      return json({
        ok: true,
        service: "infinite-canvas-commercial-api",
      });
    }

    // 注册
    if (req.method === "POST" && url.pathname === "/api/auth/register") {
      try {
        const body = (await req.json()) as {
          username?: string;
          password?: string;
        };

        const username = body.username?.trim() || "";
        const password = body.password || "";

        if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
          return json(
            { error: "用户名需为 3-32 位英文、数字、_、- 或 ." },
            400,
          );
        }

        if (password.length < 8 || password.length > 72) {
          return json({ error: "密码长度需为 8-72 位" }, 400);
        }

        const exists = db
          .query("SELECT id FROM users WHERE username = ?")
          .get(username);

        if (exists) {
          return json({ error: "用户名已存在" }, 409);
        }

        const passwordHash = await Bun.password.hash(password);

        const result = db
          .query(`
            INSERT INTO users (username, password_hash, credits)
            VALUES (?, ?, ?)
          `)
          .run(username, passwordHash, INITIAL_CREDITS);

        const user = db
          .query(`
            SELECT id, username, role, credits, created_at
            FROM users
            WHERE id = ?
          `)
          .get(result.lastInsertRowid);

        return json(
          {
            token: createLoginToken(user),
            user,
          },
          201,
        );
      } catch {
        return json({ error: "注册失败" }, 400);
      }
    }

    // 登录
    if (req.method === "POST" && url.pathname === "/api/auth/login") {
      try {
        const body = (await req.json()) as {
          username?: string;
          password?: string;
        };

        const username = body.username?.trim() || "";
        const password = body.password || "";

        const user = db
          .query(`
            SELECT id, username, password_hash, role, credits, created_at
            FROM users
            WHERE username = ?
          `)
          .get(username) as any;

        if (!user) {
          return json({ error: "用户名或密码错误" }, 401);
        }

        const valid = await Bun.password.verify(
          password,
          user.password_hash,
        );

        if (!valid) {
          return json({ error: "用户名或密码错误" }, 401);
        }

        delete user.password_hash;

        return json({
          token: createLoginToken(user),
          user,
        });
      } catch {
        return json({ error: "登录失败" }, 400);
      }
    }

    // 当前用户
    if (req.method === "GET" && url.pathname === "/api/me") {
      const user = getCurrentUser(req);

      if (!user) {
        return json({ error: "未登录" }, 401);
      }

      return json({ user });
    }

    return json({ error: "Not Found" }, 404);
  },
});

console.log(`Commercial API running on :${PORT}`);
