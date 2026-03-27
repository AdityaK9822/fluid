"use client";

import { useState } from "react";
import { Smartphone, X, CheckCircle, AlertCircle } from "lucide-react";

interface ConnectDeviceDialogProps {
  serverUrl: string;
  adminToken: string;
}

type Status = "idle" | "loading" | "success" | "error";

export function ConnectDeviceDialog({ serverUrl, adminToken }: ConnectDeviceDialogProps) {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState("");
  const [label, setLabel] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setStatus("loading");
    setMessage("");

    try {
      const res = await fetch(`${serverUrl}/admin/device-tokens`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-admin-token": adminToken,
        },
        body: JSON.stringify({ token: token.trim(), label: label.trim() || undefined }),
      });

      if (res.status === 201) {
        setStatus("success");
        setMessage("Device registered successfully. You will now receive push notifications.");
        setToken("");
        setLabel("");
      } else if (res.status === 409) {
        setStatus("error");
        setMessage("This device token is already registered.");
      } else {
        const data = await res.json().catch(() => ({}));
        setStatus("error");
        setMessage((data as any).error ?? "Failed to register device token.");
      }
    } catch {
      setStatus("error");
      setMessage("Could not reach the server. Check your connection.");
    }
  }

  function handleClose() {
    setOpen(false);
    setStatus("idle");
    setMessage("");
    setToken("");
    setLabel("");
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex min-h-10 items-center justify-center gap-2 rounded-full border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 transition hover:border-slate-400 hover:bg-slate-50"
      >
        <Smartphone className="h-4 w-4" />
        Connect Device
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
          onClick={(e) => e.target === e.currentTarget && handleClose()}
        >
          <div className="relative w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
            <button
              type="button"
              onClick={handleClose}
              className="absolute right-4 top-4 rounded-full p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-sky-100">
                <Smartphone className="h-5 w-5 text-sky-600" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-slate-900">Connect Device</h2>
                <p className="text-sm text-slate-500">
                  Register your FCM token to receive push notifications.
                </p>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="mt-5 space-y-4">
              <div>
                <label
                  htmlFor="fcm-token"
                  className="block text-sm font-medium text-slate-700"
                >
                  FCM Device Token <span className="text-red-500">*</span>
                </label>
                <textarea
                  id="fcm-token"
                  rows={3}
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="Paste your Firebase Cloud Messaging registration token here"
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder-slate-400 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                  required
                />
                <p className="mt-1 text-xs text-slate-500">
                  Obtain this token from your mobile app via{" "}
                  <code className="rounded bg-slate-100 px-1">
                    FirebaseMessaging.getInstance().getToken()
                  </code>
                </p>
              </div>

              <div>
                <label
                  htmlFor="device-label"
                  className="block text-sm font-medium text-slate-700"
                >
                  Label <span className="text-slate-400">(optional)</span>
                </label>
                <input
                  id="device-label"
                  type="text"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  placeholder="e.g. My iPhone 15"
                  className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder-slate-400 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
                />
              </div>

              {message && (
                <div
                  className={`flex items-start gap-2 rounded-lg px-3 py-2 text-sm ${
                    status === "success"
                      ? "bg-green-50 text-green-800"
                      : "bg-red-50 text-red-800"
                  }`}
                >
                  {status === "success" ? (
                    <CheckCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  ) : (
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  )}
                  {message}
                </div>
              )}

              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={handleClose}
                  className="rounded-full border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  {status === "success" ? "Close" : "Cancel"}
                </button>
                {status !== "success" && (
                  <button
                    type="submit"
                    disabled={status === "loading" || !token.trim()}
                    className="rounded-full bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
                  >
                    {status === "loading" ? "Registering…" : "Register Device"}
                  </button>
                )}
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
}
