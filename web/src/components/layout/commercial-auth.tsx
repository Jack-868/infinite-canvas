import { useEffect, useState } from "react";
import { Button, Dropdown, Input, Modal, Segmented, Tag } from "antd";
import { Coins, LogOut, Shield, UserRound } from "lucide-react";

type User = {
  id: number;
  username: string;
  role: string;
  credits: number;
  created_at: string;
};

const TOKEN_KEY = "infinite_canvas_commercial_token";

export function CommercialAuth() {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"login" | "register">("login");

  const [user, setUser] = useState<User | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadUser(token: string) {
    try {
      const response = await fetch("/api/me", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        localStorage.removeItem(TOKEN_KEY);
        setUser(null);
        return;
      }

      const data = await response.json();
      setUser(data.user);
    } catch {
      setUser(null);
    }
  }

  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY);

    if (token) {
      void loadUser(token);
    }
  }, []);

  async function submit() {
    setError("");

    if (!username.trim() || !password) {
      setError("请输入用户名和密码");
      return;
    }

    setLoading(true);

    try {
      const endpoint =
        mode === "login"
          ? "/api/auth/login"
          : "/api/auth/register";

      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username: username.trim(),
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.error || "操作失败");
        return;
      }

      localStorage.setItem(TOKEN_KEY, data.token);
      setUser(data.user);

      setUsername("");
      setPassword("");
      setError("");
      setOpen(false);
    } catch {
      setError("网络异常，请稍后重试");
    } finally {
      setLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    setUser(null);
  }

  if (user) {
    return (
      <Dropdown
        trigger={["click"]}
        menu={{
          items: [
            {
              key: "user",
              disabled: true,
              label: (
                <div className="min-w-40 py-1">
                  <div className="flex items-center gap-2 font-medium">
                    <UserRound className="size-4" />
                    {user.username}
                  </div>

                  <div className="mt-2 flex items-center gap-2 text-xs">
                    <Coins className="size-4" />
                    <span>算力点</span>
                    <strong>{user.credits}</strong>
                  </div>

                  {user.role === "admin" ? (
                    <div className="mt-2">
                      <Tag color="gold">
                        <Shield className="mr-1 inline size-3" />
                        管理员
                      </Tag>
                    </div>
                  ) : null}
                </div>
              ),
            },
            {
              type: "divider",
            },
            {
              key: "logout",
              icon: <LogOut className="size-4" />,
              label: "退出登录",
              onClick: logout,
            },
          ],
        }}
      >
        <Button type="text" className="!px-2">
          <span className="flex items-center gap-1.5">
            <Coins className="size-4" />
            <span>{user.credits}</span>
            <span className="hidden sm:inline">{user.username}</span>
          </span>
        </Button>
      </Dropdown>
    );
  }

  return (
    <>
      <Button
        type="text"
        className="!px-2"
        onClick={() => {
          setMode("login");
          setError("");
          setOpen(true);
        }}
      >
        登录
      </Button>

      <Modal
        title={mode === "login" ? "账号登录" : "注册账号"}
        open={open}
        footer={null}
        destroyOnHidden
        onCancel={() => {
          setOpen(false);
          setError("");
        }}
      >
        <div className="pt-2">
          <Segmented
            block
            value={mode}
            options={[
              { label: "登录", value: "login" },
              { label: "注册", value: "register" },
            ]}
            onChange={(value) => {
              setMode(value as "login" | "register");
              setError("");
            }}
          />

          <div className="mt-5 space-y-4">
            <div>
              <div className="mb-1.5 text-sm">用户名</div>

              <Input
                size="large"
                value={username}
                placeholder="请输入用户名"
                autoComplete="username"
                onChange={(e) => setUsername(e.target.value)}
                onPressEnter={() => void submit()}
              />
            </div>

            <div>
              <div className="mb-1.5 text-sm">密码</div>

              <Input.Password
                size="large"
                value={password}
                placeholder={
                  mode === "register"
                    ? "至少 8 位密码"
                    : "请输入密码"
                }
                autoComplete={
                  mode === "login"
                    ? "current-password"
                    : "new-password"
                }
                onChange={(e) => setPassword(e.target.value)}
                onPressEnter={() => void submit()}
              />
            </div>

            {mode === "register" ? (
              <div className="text-xs text-stone-500">
                注册成功后自动获得初始算力点。
              </div>
            ) : null}

            {error ? (
              <div className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-600 dark:bg-red-950/30 dark:text-red-400">
                {error}
              </div>
            ) : null}

            <Button
              type="primary"
              size="large"
              block
              loading={loading}
              onClick={() => void submit()}
            >
              {mode === "login" ? "登录" : "立即注册"}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
}
