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

db.run(`
  CREATE TABLE IF NOT EXISTS credit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    admin_id INTEGER,
    delta INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    remark TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`);

type TokenPayload = {
  sub: number;
  username: string;
  role: string;
  exp: number;
};

type UserRow = {
  id: number;
  username: string;
  role: string;
  credits: number;
  created_at: string;
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
  const body = Buffer.from(
    JSON.stringify(payload),
  ).toString("base64url");

  const signature = createHmac("sha256", JWT_SECRET)
    .update(body)
    .digest("base64url");

  return `${body}.${signature}`;
}

function verifyToken(token: string): TokenPayload | null {
  try {
    const [body, signature] = token.split(".");

    if (!body || !signature) {
      return null;
    }

    const expected = createHmac("sha256", JWT_SECRET)
      .update(body)
      .digest("base64url");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !timingSafeEqual(a, b)
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8"),
    ) as TokenPayload;

    if (
      payload.exp <
      Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function getCurrentUser(
  req: Request,
): UserRow | null {
  const auth = req.headers.get("authorization");

  if (!auth?.startsWith("Bearer ")) {
    return null;
  }

  const payload = verifyToken(auth.slice(7));

  if (!payload) {
    return null;
  }

  return (
    db
      .query(`
        SELECT
          id,
          username,
          role,
          credits,
          created_at
        FROM users
        WHERE id = ?
      `)
      .get(payload.sub) as UserRow | null
  );
}

function getAdmin(req: Request) {
  const user = getCurrentUser(req);

  if (!user) {
    return {
      error: json({ error: "未登录" }, 401),
      user: null,
    };
  }

  if (user.role !== "admin") {
    return {
      error: json(
        { error: "无管理员权限" },
        403,
      ),
      user: null,
    };
  }

  return {
    error: null,
    user,
  };
}

function createLoginToken(user: UserRow) {
  return signToken({
    sub: user.id,
    username: user.username,
    role: user.role,
    exp:
      Math.floor(Date.now() / 1000) +
      7 * 24 * 60 * 60,
  });
}

// 第一次启动自动创建管理员。
// 管理员已经存在时，不会覆盖原密码。
const existingAdmin = db
  .query(
    "SELECT id FROM users WHERE username = ?",
  )
  .get(ADMIN_USERNAME);

if (!existingAdmin && ADMIN_PASSWORD) {
  const hash = await Bun.password.hash(
    ADMIN_PASSWORD,
  );

  db.query(`
    INSERT INTO users (
      username,
      password_hash,
      role,
      credits
    )
    VALUES (?, ?, 'admin', 0)
  `).run(ADMIN_USERNAME, hash);

  console.log(
    `管理员 ${ADMIN_USERNAME} 创建成功`,
  );
}

Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,

  async fetch(req) {
    const url = new URL(req.url);

    // =========================
    // 健康检查
    // =========================
    if (
      req.method === "GET" &&
      url.pathname === "/api/health"
    ) {
      return json({
        ok: true,
        service:
          "infinite-canvas-commercial-api",
      });
    }

    // =========================
    // 注册
    // =========================
    if (
      req.method === "POST" &&
      url.pathname === "/api/auth/register"
    ) {
      try {
        const body = (await req.json()) as {
          username?: string;
          password?: string;
        };

        const username =
          body.username?.trim() || "";

        const password =
          body.password || "";

        if (
          !/^[A-Za-z0-9_.-]{3,32}$/.test(
            username,
          )
        ) {
          return json(
            {
              error:
                "用户名需为 3-32 位英文、数字、_、- 或 .",
            },
            400,
          );
        }

        if (
          password.length < 8 ||
          password.length > 72
        ) {
          return json(
            {
              error:
                "密码长度需为 8-72 位",
            },
            400,
          );
        }

        const exists = db
          .query(
            "SELECT id FROM users WHERE username = ?",
          )
          .get(username);

        if (exists) {
          return json(
            {
              error: "用户名已存在",
            },
            409,
          );
        }

        const passwordHash =
          await Bun.password.hash(password);

        const result = db
          .query(`
            INSERT INTO users (
              username,
              password_hash,
              credits
            )
            VALUES (?, ?, ?)
          `)
          .run(
            username,
            passwordHash,
            INITIAL_CREDITS,
          );

        const user = db
          .query(`
            SELECT
              id,
              username,
              role,
              credits,
              created_at
            FROM users
            WHERE id = ?
          `)
          .get(
            result.lastInsertRowid,
          ) as UserRow;

        return json(
          {
            token:
              createLoginToken(user),
            user,
          },
          201,
        );
      } catch (error) {
        console.error(
          "register error:",
          error,
        );

        return json(
          {
            error: "注册失败",
          },
          400,
        );
      }
    }

    // =========================
    // 登录
    // =========================
    if (
      req.method === "POST" &&
      url.pathname === "/api/auth/login"
    ) {
      try {
        const body = (await req.json()) as {
          username?: string;
          password?: string;
        };

        const username =
          body.username?.trim() || "";

        const password =
          body.password || "";

        const user = db
          .query(`
            SELECT
              id,
              username,
              password_hash,
              role,
              credits,
              created_at
            FROM users
            WHERE username = ?
          `)
          .get(username) as
          | (UserRow & {
              password_hash: string;
            })
          | null;

        if (!user) {
          return json(
            {
              error:
                "用户名或密码错误",
            },
            401,
          );
        }

        const valid =
          await Bun.password.verify(
            password,
            user.password_hash,
          );

        if (!valid) {
          return json(
            {
              error:
                "用户名或密码错误",
            },
            401,
          );
        }

        const publicUser: UserRow = {
          id: user.id,
          username: user.username,
          role: user.role,
          credits: user.credits,
          created_at: user.created_at,
        };

        return json({
          token:
            createLoginToken(publicUser),
          user: publicUser,
        });
      } catch (error) {
        console.error(
          "login error:",
          error,
        );

        return json(
          {
            error: "登录失败",
          },
          400,
        );
      }
    }

    // =========================
    // 当前用户
    // =========================
    if (
      req.method === "GET" &&
      url.pathname === "/api/me"
    ) {
      const user =
        getCurrentUser(req);

      if (!user) {
        return json(
          {
            error: "未登录",
          },
          401,
        );
      }

      return json({
        user,
      });
    }

    // =========================
    // 管理员：用户列表
    // =========================
    if (
      req.method === "GET" &&
      url.pathname === "/api/admin/users"
    ) {
      const admin = getAdmin(req);

      if (admin.error) {
        return admin.error;
      }

      const users = db
        .query(`
          SELECT
            id,
            username,
            role,
            credits,
            created_at
          FROM users
          ORDER BY id DESC
        `)
        .all();

      return json({
        users,
      });
    }

    // =========================
    // 管理员：调整算力点
    //
    // POST
    // /api/admin/users/:id/credits
    //
    // body:
    // {
    //   "delta": 100,
    //   "remark": "后台充值"
    // }
    // =========================
    const creditMatch =
      url.pathname.match(
        /^\/api\/admin\/users\/(\d+)\/credits$/,
      );

    if (
      req.method === "POST" &&
      creditMatch
    ) {
      const admin = getAdmin(req);

      if (admin.error || !admin.user) {
        return admin.error!;
      }

      try {
        const userId = Number(
          creditMatch[1],
        );

        const body =
          (await req.json()) as {
            delta?: number;
            remark?: string;
          };

        const delta = Math.trunc(
          Number(body.delta),
        );

        if (
          !Number.isFinite(delta) ||
          delta === 0
        ) {
          return json(
            {
              error:
                "请输入正确的算力点调整数量",
            },
            400,
          );
        }

        if (Math.abs(delta) > 10000000) {
          return json(
            {
              error:
                "单次调整数量过大",
            },
            400,
          );
        }

        const target = db
          .query(`
            SELECT
              id,
              username,
              role,
              credits,
              created_at
            FROM users
            WHERE id = ?
          `)
          .get(userId) as UserRow | null;

        if (!target) {
          return json(
            {
              error: "用户不存在",
            },
            404,
          );
        }

        const newCredits = Math.max(
          0,
          Number(target.credits) +
            delta,
        );

        db.query(`
          UPDATE users
          SET credits = ?
          WHERE id = ?
        `).run(
          newCredits,
          userId,
        );

        db.query(`
          INSERT INTO credit_logs (
            user_id,
            admin_id,
            delta,
            balance_after,
            remark
          )
          VALUES (?, ?, ?, ?, ?)
        `).run(
          userId,
          admin.user.id,
          delta,
          newCredits,
          body.remark?.trim() ||
            "管理员后台调整",
        );

        const user = db
          .query(`
            SELECT
              id,
              username,
              role,
              credits,
              created_at
            FROM users
            WHERE id = ?
          `)
          .get(userId);

        return json({
          ok: true,
          user,
        });
      } catch (error) {
        console.error(
          "credits error:",
          error,
        );

        return json(
          {
            error:
              "调整算力点失败",
          },
          400,
        );
      }
    }

    // =========================
    // 管理员：重置普通用户密码
    //
    // POST
    // /api/admin/users/:id/password
    //
    // body:
    // {
    //   "password": "12345678"
    // }
    // =========================
    const passwordMatch =
      url.pathname.match(
        /^\/api\/admin\/users\/(\d+)\/password$/,
      );

    if (
      req.method === "POST" &&
      passwordMatch
    ) {
      const admin = getAdmin(req);

      if (admin.error) {
        return admin.error;
      }

      try {
        const userId = Number(
          passwordMatch[1],
        );

        const body =
          (await req.json()) as {
            password?: string;
          };

        const password =
          body.password || "";

        if (
          password.length < 8 ||
          password.length > 72
        ) {
          return json(
            {
              error:
                "新密码长度需为 8-72 位",
            },
            400,
          );
        }

        const target = db
          .query(`
            SELECT
              id,
              username,
              role
            FROM users
            WHERE id = ?
          `)
          .get(userId) as
          | {
              id: number;
              username: string;
              role: string;
            }
          | null;

        if (!target) {
          return json(
            {
              error: "用户不存在",
            },
            404,
          );
        }

        if (target.role === "admin") {
          return json(
            {
              error:
                "后台暂不允许重置管理员密码",
            },
            400,
          );
        }

        const passwordHash =
          await Bun.password.hash(
            password,
          );

        db.query(`
          UPDATE users
          SET password_hash = ?
          WHERE id = ?
        `).run(
          passwordHash,
          userId,
        );

        return json({
          ok: true,
        });
      } catch (error) {
        console.error(
          "password reset error:",
          error,
        );

        return json(
          {
            error:
              "重置密码失败",
          },
          400,
        );
      }
    }

    // =========================
    // 管理员：删除普通用户
    // =========================
    const deleteMatch =
      url.pathname.match(
        /^\/api\/admin\/users\/(\d+)$/,
      );

    if (
      req.method === "DELETE" &&
      deleteMatch
    ) {
      const admin = getAdmin(req);

      if (admin.error || !admin.user) {
        return admin.error!;
      }

      const userId = Number(
        deleteMatch[1],
      );

      if (
        userId === admin.user.id
      ) {
        return json(
          {
            error:
              "不能删除当前管理员账号",
          },
          400,
        );
      }

      const target = db
        .query(`
          SELECT
            id,
            username,
            role
          FROM users
          WHERE id = ?
        `)
        .get(userId) as
        | {
            id: number;
            username: string;
            role: string;
          }
        | null;

      if (!target) {
        return json(
          {
            error: "用户不存在",
          },
          404,
        );
      }

      if (target.role === "admin") {
        return json(
          {
            error:
              "不能删除管理员账号",
          },
          400,
        );
      }

      db.query(`
        DELETE FROM users
        WHERE id = ?
      `).run(userId);

      return json({
        ok: true,
      });
    }

    return json(
      {
        error: "Not Found",
      },
      404,
    );
  },
});

console.log(
  `Commercial API running on :${PORT}`,
);
