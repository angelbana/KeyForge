import { configHostBlock } from "../shared/config";
import React, { Component, useEffect, useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import type {
  Algorithm,
  Api,
  Capabilities,
  ConfigDocument,
  GenerateRequest,
  KeyScan,
  Prompt,
  Result,
  Server,
  HardwareState,
} from "../shared/types";
import { en, ru, type Language, type TextKey } from "./i18n";
import "./style.css";
import { themes, readTheme, applyTheme, type Theme } from "./design";
import {
  FingerprintBadge,
  StrengthIndicator,
  HardwareIndicator,
} from "./components";
declare global {
  interface Window {
    keyforge?: Api;
  }
}
type Tab = "explorer" | "generate" | "hardware" | "servers";
const api = window.keyforge;
const initialRequest: GenerateRequest = {
  algorithm: "ed25519",
  bits: 256,
  name: "id_ed25519",
  comment: "",
  passphrase: "",
  resident: false,
  verifyRequired: false,
};
function Icon({ type }: { type: Tab | "brand" }) {
  const paths = {
    brand: "M8 14a5 5 0 1 1 4-8L22 6v4h-3v3h-4l-3 3a5 5 0 0 1-4-2Z",
    explorer: "M4 5h16v14H4z M8 9h8 M8 13h5",
    generate: "M12 4v16 M4 12h16",
    hardware: "M8 3h8v18H8z M11 7h2 M11 17h2",
    servers: "M4 4h16v6H4z M4 14h16v6H4z M7 7h1 M7 17h1",
  };
  return (
    <svg
      viewBox="0 0 24 24"
      width="23"
      height="23"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[type]} />
    </svg>
  );
}
class ErrorBoundary extends Component<
  { children: React.ReactNode },
  { failed: boolean }
> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <main className="fallback">
        <h1>KeyForge</h1>
        <p>Не удалось открыть интерфейс / Unable to render the interface.</p>
        <button onClick={() => location.reload()}>
          Перезапустить / Restart
        </button>
      </main>
    ) : (
      this.props.children
    );
  }
}
function App() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  const [hardwareState, setHardwareState] = useState<HardwareState>("unknown");
  const hardwareBaseline = useRef<HardwareState>("unknown");
  const [copiedAction, setCopiedAction] = useState<string | null>(null);
  useEffect(() => applyTheme(theme), [theme]);
  useEffect(() => {
    if (!copiedAction) return;
    const timer = setTimeout(() => setCopiedAction(null), 1800);
    return () => clearTimeout(timer);
  }, [copiedAction]);
  const [lang, setLang] = useState<Language>(() => {
    try {
      return localStorage.getItem("keyforge.language") === "en" ? "en" : "ru";
    } catch {
      return "ru";
    }
  });
  const t = (key: TextKey) => (lang === "ru" ? ru : en)[key];
  const [tab, setTab] = useState<Tab>("explorer");
  const [scan, setScan] = useState<KeyScan>({
    directory: "",
    keys: [],
    warnings: [],
  });
  const [caps, setCaps] = useState<Capabilities>();
  const [selected, setSelected] = useState("");
  const [installOpen, setInstallOpen] = useState(false);
  const [installUser, setInstallUser] = useState("");
  const [installCommand, setInstallCommand] = useState("");
  const [request, setRequest] = useState(initialRequest);
  const [allowEmpty, setAllowEmpty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState<TextKey>();
  const [config, setConfig] = useState<ConfigDocument>();
  const [configText, setConfigText] = useState("");
  const [resolved, setResolved] = useState("");
  const [server, setServer] = useState<Server>({
    host: "",
    user: "",
    port: 22,
    keyName: "",
  });
  const [alias, setAlias] = useState("");
  const [snippets, setSnippets] = useState<{
    powershell: string;
    posix: string;
  }>();
  const [prompt, setPrompt] = useState<Prompt>();
  const [answer, setAnswer] = useState("");
  useEffect(() => {
    document.documentElement.lang = lang;
    try {
      localStorage.setItem("keyforge.language", lang);
    } catch {
      /* optional preference */
    }
  }, [lang]);
  async function unwrap<T>(result: Promise<Result<T>>): Promise<T> {
    const value = await result;
    if (!value.ok) throw new Error(value.error);
    return value.value;
  }
  async function refresh() {
    if (!api) return;
    const value = await unwrap(api.scan());
    setInstallCommand("");
    setSnippets(undefined);
    setScan(value);
    setSelected((old) =>
      value.keys.some((key) => key.name === old)
        ? old
        : value.keys[0]?.name || "",
    );
    setServer((old) => ({
      ...old,
      keyName: value.keys.some((key) => key.name === old.keyName)
        ? old.keyName
        : value.keys[0]?.name || "",
    }));
  }
  async function loadConfig() {
    if (!api) return;
    const value = await unwrap(api.config());
    setConfig(value);
    setConfigText(value.text);
  }
  async function act(action: () => Promise<unknown>, success?: TextKey) {
    setBusy(true);
    setError("");
    setNotice(undefined);
    try {
      await action();
      if (success) setNotice(success);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "operationFailed");
    } finally {
      setHardwareState(hardwareBaseline.current);
      setBusy(false);
      setPrompt(undefined);
      setAnswer("");
    }
  }
  useEffect(() => {
    if (!api) return;
    void act(async () => {
      await Promise.all([
        refresh(),
        loadConfig(),
        unwrap(api.capabilities()).then(setCaps),
        refreshHardware(),
      ]);
    });
    const stopPrompt = api.onPrompt((value) => {
      setAnswer("");
      setPrompt(value);
    });
    const stopHardware = api.onHardwareState(setHardwareState);
    return () => {
      stopPrompt();
      stopHardware();
    };
  }, []);
  async function refreshHardware() {
    if (!api) return;
    const state = await unwrap(api.hardwareState());
    hardwareBaseline.current = state;
    setHardwareState(state);
  }
  async function copyPublic(name: string) {
    await unwrap(api!.copyPublic(name));
    setCopiedAction(`public:${name}`);
  }
  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      if (prompt) return;
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
      if (event.key.toLowerCase() === "k") {
        event.preventDefault();
        setTab("explorer");
        requestAnimationFrame(() =>
          (
            document.querySelector(".key-item.selected") as HTMLElement | null
          )?.focus(),
        );
      } else if (
        event.key.toLowerCase() === "c" &&
        tab === "explorer" &&
        selected &&
        !busy
      ) {
        const target = event.target as HTMLElement;
        if (
          target.isContentEditable ||
          /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) ||
          window.getSelection()?.toString()
        )
          return;
        event.preventDefault();
        void act(() => copyPublic(selected));
      }
    };
    document.addEventListener("keydown", listener);
    return () => document.removeEventListener("keydown", listener);
  }, [tab, selected, busy, prompt]);
  const key = scan.keys.find((value) => value.name === selected);
  const strength: TextKey = !request.passphrase.length
    ? "none"
    : request.passphrase.length < 12
      ? "weak"
      : request.passphrase.length < 20
        ? "fair"
        : "strong";
  const update = <K extends keyof GenerateRequest>(
    field: K,
    value: GenerateRequest[K],
  ) => setRequest((old) => ({ ...old, [field]: value }));
  const hardware = request.algorithm.endsWith("-sk");
  useEffect(() => {
    if (
      !api ||
      busy ||
      (tab !== "hardware" && !(tab === "generate" && hardware)) ||
      hardwareBaseline.current === "unknown"
    )
      return;
    let disposed = false,
      probing = false;
    const timer = setInterval(async () => {
      if (probing) return;
      probing = true;
      try {
        const result = await api.hardwareState();
        if (!disposed && result.ok) {
          hardwareBaseline.current = result.value;
          setHardwareState(result.value);
        }
      } finally {
        probing = false;
      }
    }, 5000);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, [tab, busy, hardware]);
  const hardwareLabel = t(
    (
      {
        unknown: "hardwareUnknown",
        absent: "hardwareAbsent",
        ready: "hardwareReady",
        touch: "hardwareTouch",
      } as const
    )[hardwareState],
  );
  const shortcut = caps?.platform === "darwin" ? "⌘" : "Ctrl+";
  const errorText = error in en ? t(error as TextKey) : t("operationFailed");
  function chooseAlgorithm(algorithm: Algorithm) {
    setRequest((old) => ({
      ...old,
      algorithm,
      bits: algorithm === "rsa" ? 4096 : algorithm === "ecdsa" ? 384 : 256,
      name: `id_${algorithm.replace("-", "_")}`,
      targetPath: undefined,
      resident: false,
      verifyRequired: false,
    }));
  }
  async function appendHost() {
    if (!api) return;
    await unwrap(api.snippets(server));
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(alias))
      throw new Error("invalidHost");
    const text = configHostBlock({
      aliases: alias,
      hostName: server.host,
      user: server.user,
      port: String(server.port),
      identityFile: `~/.ssh/${server.keyName}`,
    });
    setConfigText((old) => `${text}\n${old}`); // Specific hosts precede wildcard defaults; preserve every existing line.
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <Icon type="brand" />
          </span>
          <strong>KeyForge</strong>
        </div>
        <p className="tagline">{t("tagline")}</p>
        <nav aria-label="KeyForge">
          {(["explorer", "generate", "hardware", "servers"] as Tab[]).map(
            (value) => (
              <button
                key={value}
                className={tab === value ? "nav-item active" : "nav-item"}
                onClick={() => setTab(value)}
              >
                <Icon type={value} />
                {t(value)}
                {value === "explorer" && <kbd>{shortcut}K</kbd>}
              </button>
            ),
          )}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-status">
            <span className="status-dot" />
            {t("local")}
          </div>
          <label className="language">
            {t("language")}
            <select
              value={lang}
              onChange={(event) => setLang(event.target.value as Language)}
            >
              <option value="ru">Русский</option>
              <option value="en">English</option>
            </select>
          </label>
          <label className="theme-control">
            {t("theme")}
            <select
              value={theme}
              onChange={(event) => setTheme(event.target.value as Theme)}
            >
              {themes.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <small>KeyForge 0.1.2</small>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div>
            <span className="section-icon">
              <Icon type={tab} />
            </span>
            <h1>{t(tab)}</h1>
          </div>
          <button
            disabled={busy || !api}
            onClick={() =>
              void act(async () => {
                await refresh();
                await refreshHardware();
              })
            }
          >
            {t("refresh")}
          </button>
        </header>
        <div className="workspace">
          {!api && <div className="alert">{t("desktopOnly")}</div>}
          {error && (
            <div role="alert" className="alert error">
              <strong>{t("errorTitle")}</strong>
              <p>{errorText}</p>
              <button onClick={() => setError("")}>×</button>
            </div>
          )}
          {notice && (
            <div role="status" className="alert success">
              {t(notice)}
            </div>
          )}
          {busy && (
            <div role="status" className="alert">
              {t("busy")}
              <button onClick={() => void api?.cancel()}>{t("cancel")}</button>
            </div>
          )}
          {tab === "explorer" && (
            <>
              <div className="metrics">
                {[
                  [scan.keys.length, "keys"],
                  [
                    scan.keys.filter((item) => item.encrypted).length,
                    "protected",
                  ],
                  [
                    scan.keys.filter((item) => item.type.startsWith("sk-"))
                      .length,
                    "hardwareKeys",
                  ],
                ].map(([count, label]) => (
                  <div className="metric" key={label}>
                    <strong>{count}</strong>
                    <span>{t(label as TextKey)}</span>
                  </div>
                ))}
              </div>
              <div className="directory">
                <span>{t("directory")}</span>
                <code>{scan.directory || "~/.ssh"}</code>
              </div>
              {!!scan.warnings.length && (
                <div className="alert">{t("warnings")}</div>
              )}
              {scan.keys.length ? (
                <div className="explorer-grid">
                  <section className="key-list" aria-label={t("keys")}>
                    <table className="key-table">
                      <thead>
                        <tr>
                          <th>{t("name")}</th>
                          <th>{t("algorithm")}</th>
                          <th>{t("bits")}</th>
                          <th>{t("protection")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scan.keys.map((item) => (
                          <tr
                            key={item.name}
                            data-selected={item.name === selected}
                          >
                            <td>
                              <button
                                className={
                                  item.name === selected
                                    ? "key-item selected"
                                    : "key-item"
                                }
                                disabled={busy}
                                onClick={() => {
                                  setSelected(item.name);
                                  setInstallCommand("");
                                  setCopiedAction(null);
                                }}
                              >
                                <strong>{item.name}</strong>
                                <small>{item.comment || "—"}</small>
                              </button>
                            </td>
                            <td>
                              <code>
                                {item.type.includes("ed25519")
                                  ? "Ed25519"
                                  : item.type.includes("ecdsa")
                                    ? "ECDSA"
                                    : "RSA"}
                                {item.type.startsWith("sk-") ? "-sk" : ""}
                              </code>
                            </td>
                            <td>
                              <code>{item.bits}</code>
                            </td>
                            <td>
                              {t(
                                !item.privatePresent || item.encrypted === null
                                  ? "unknown"
                                  : item.encrypted
                                    ? "encrypted"
                                    : "unencrypted",
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </section>
                  {key && (
                    <section className="key-detail">
                      <div className="detail-heading">
                        <h2>{key.name}</h2>
                        <span className="pill">{key.type}</span>
                      </div>
                      <dl>
                        {[
                          [t("comment"), key.comment || "—"],
                          [t("fingerprint"), key.fingerprint],
                          [
                            t("path"),
                            key.privatePresent ? key.path : t("publicOnly"),
                          ],
                          [
                            t("encryption"),
                            !key.privatePresent
                              ? t("publicOnly")
                              : t(
                                  key.encrypted === null
                                    ? "unknown"
                                    : key.encrypted
                                      ? "encrypted"
                                      : "unencrypted",
                                ),
                          ],
                          [
                            t("permissions"),
                            t(
                              key.permissions === "restricted"
                                ? "restricted"
                                : key.permissions === "open"
                                  ? "open"
                                  : "unknown",
                            ),
                          ],
                          [
                            t("modified"),
                            new Date(key.modified).toLocaleString(
                              lang === "ru" ? "ru-RU" : "en-US",
                            ),
                          ],
                        ].map(([label, value]) => (
                          <div key={label}>
                            <dt>{label}</dt>
                            <dd>
                              {label === t("fingerprint") ? (
                                <FingerprintBadge value={value} />
                              ) : (
                                value
                              )}
                            </dd>
                          </div>
                        ))}
                      </dl>
                      <button
                        className="primary"
                        data-copied={copiedAction === `public:${key.name}`}
                        aria-live="polite"
                        disabled={busy || !api}
                        onClick={() => void act(() => copyPublic(key.name))}
                      >
                        {t(
                          copiedAction === `public:${key.name}`
                            ? "copiedInline"
                            : "copy",
                        )}
                        <kbd>{shortcut}C</kbd>
                      </button>
                      <button
                        disabled={busy || !api}
                        aria-expanded={installOpen}
                        onClick={() => setInstallOpen((open) => !open)}
                      >
                        {t("installOnServer")}
                      </button>
                      {installOpen && (
                        <section className="server-install">
                          <p className="muted">{t("serverCommandHint")}</p>
                          <label>
                            {t("serverUser")}
                            <input
                              disabled={busy}
                              value={installUser}
                              maxLength={64}
                              onChange={(event) => {
                                setInstallUser(event.target.value);
                                setInstallCommand("");
                              }}
                            />
                          </label>
                          <div className="actions">
                            <button
                              className="prepare-server-command"
                              disabled={busy || !api}
                              onClick={() =>
                                void act(async () =>
                                  setInstallCommand(
                                    await unwrap(
                                      api!.serverCommand(key.name, installUser),
                                    ),
                                  ),
                                )
                              }
                            >
                              {t("prepareServerCommand")}
                            </button>
                          </div>
                          {installCommand && (
                            <>
                              <pre>{installCommand}</pre>
                              <button
                                className="copy-server-command primary"
                                data-copied={copiedAction === "server"}
                                disabled={busy || !api}
                                onClick={() =>
                                  void act(async () => {
                                    setInstallCommand(
                                      await unwrap(
                                        api!.copyServerCommand(
                                          key.name,
                                          installUser,
                                        ),
                                      ),
                                    );
                                    setCopiedAction("server");
                                  })
                                }
                              >
                                {t(
                                  copiedAction === "server"
                                    ? "copiedInline"
                                    : "copyCommand",
                                )}
                              </button>
                            </>
                          )}
                        </section>
                      )}
                      {key.privatePresent && (
                        <button
                          disabled={busy || !api}
                          onClick={() => {
                            if (confirm(t("confirmRepair")))
                              void act(async () => {
                                await unwrap(api!.repairPermissions(key.name));
                                await refresh();
                              }, "repaired");
                          }}
                        >
                          {t("repair")}
                        </button>
                      )}
                      <p className="boundary">{t("privateBoundary")}</p>
                    </section>
                  )}
                </div>
              ) : (
                <section className="empty">
                  <span className="empty-icon">
                    <Icon type="brand" />
                  </span>
                  <h2>{t("empty")}</h2>
                  <p>{t("emptyHint")}</p>
                  <button
                    className="primary"
                    onClick={() => setTab("generate")}
                  >
                    {t("generate")}
                  </button>
                </section>
              )}
            </>
          )}
          {tab === "generate" && (
            <section>
              <div className="section-heading">
                <h2>{t("createTitle")}</h2>
                <p>{t("createHint")}</p>
              </div>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  const submitted = { ...request };
                  setRequest((old) => ({ ...old, passphrase: "" }));
                  setAllowEmpty(false);
                  void act(async () => {
                    try {
                      await unwrap(api!.generate(submitted));
                      await refresh();
                    } finally {
                      submitted.passphrase = "";
                    }
                  }, "created");
                }}
              >
                <div className="algorithm-grid">
                  {(
                    [
                      "ed25519",
                      "ecdsa",
                      "rsa",
                      "ed25519-sk",
                      "ecdsa-sk",
                    ] as Algorithm[]
                  ).map((value) => (
                    <button
                      type="button"
                      key={value}
                      className={
                        request.algorithm === value
                          ? "algorithm chosen"
                          : "algorithm"
                      }
                      aria-pressed={request.algorithm === value}
                      disabled={busy}
                      onClick={() => chooseAlgorithm(value)}
                    >
                      <strong>{value}</strong>
                      {value === "ed25519" && (
                        <span className="pill">{t("recommended")}</span>
                      )}
                      <p>
                        {t(value.endsWith("-sk") ? "sk" : (value as "ed25519"))}
                      </p>
                    </button>
                  ))}
                </div>
                <div className="form-panel">
                  <div className="form-grid">
                    <label>
                      {t("name")}
                      <input
                        required
                        maxLength={80}
                        pattern="[A-Za-z0-9][A-Za-z0-9._\-]*"
                        value={request.name}
                        onChange={(event) =>
                          setRequest((old) => ({
                            ...old,
                            name: event.target.value,
                            targetPath: undefined,
                          }))
                        }
                      />
                    </label>
                    <label>
                      {t("comment")}
                      <input
                        maxLength={256}
                        value={request.comment}
                        onChange={(event) =>
                          update("comment", event.target.value)
                        }
                      />
                    </label>
                    {(request.algorithm === "rsa" ||
                      request.algorithm === "ecdsa") && (
                      <label>
                        {t("bits")}
                        <select
                          value={request.bits}
                          onChange={(event) =>
                            update("bits", Number(event.target.value))
                          }
                        >
                          {(request.algorithm === "rsa"
                            ? [3072, 4096]
                            : [256, 384, 521]
                          ).map((size) => (
                            <option key={size}>{size}</option>
                          ))}
                        </select>
                      </label>
                    )}
                    <label className="wide">
                      {t("passphrase")}
                      <input
                        type="password"
                        autoComplete="new-password"
                        maxLength={1024}
                        value={request.passphrase}
                        onChange={(event) =>
                          update("passphrase", event.target.value)
                        }
                      />
                      <span className="password-tools">
                        <StrengthIndicator
                          value={request.passphrase}
                          label={t(strength)}
                        />
                        <button
                          type="button"
                          onClick={() => {
                            const bytes = crypto.getRandomValues(
                              new Uint8Array(32),
                            );
                            update(
                              "passphrase",
                              Array.from(bytes, (byte) =>
                                byte.toString(16).padStart(2, "0"),
                              ).join(""),
                            );
                          }}
                        >
                          {t("random")}
                        </button>
                      </span>
                      <small>{t("passphraseHint")}</small>
                    </label>
                  </div>
                  <label className="wide target-path">
                    {t("targetPath")}
                    <input
                      readOnly
                      value={
                        request.targetPath ||
                        `${scan.directory || "~/.ssh"}/${request.name}`
                      }
                    />
                    <button
                      type="button"
                      disabled={busy || !api}
                      onClick={() =>
                        void act(async () => {
                          const path = await unwrap(
                            api!.chooseTarget(request.name),
                          );
                          if (path) update("targetPath", path);
                        })
                      }
                    >
                      {t("choosePath")}
                    </button>
                    <small>{t("customPathHint")}</small>
                  </label>
                  {!request.passphrase && (
                    <label className="checkbox">
                      <input
                        type="checkbox"
                        checked={allowEmpty}
                        onChange={(event) =>
                          setAllowEmpty(event.target.checked)
                        }
                      />
                      {t("noPassphrase")}
                    </label>
                  )}
                  {hardware && (
                    <div className="hardware-options">
                      <HardwareIndicator
                        state={hardwareState}
                        label={hardwareLabel}
                      />
                      <label className="checkbox">
                        <input
                          type="checkbox"
                          checked={request.resident}
                          onChange={(event) =>
                            update("resident", event.target.checked)
                          }
                        />
                        {t("resident")}
                      </label>
                      <label className="checkbox">
                        <input
                          type="checkbox"
                          checked={request.verifyRequired}
                          onChange={(event) =>
                            update("verifyRequired", event.target.checked)
                          }
                        />
                        {t("verifyRequired")}
                      </label>
                    </div>
                  )}
                  <p className="muted">{t("locationHint")}</p>
                  <button
                    className="primary"
                    disabled={
                      busy ||
                      !api ||
                      !caps?.keygen ||
                      (!request.passphrase && !allowEmpty)
                    }
                  >
                    {t("create")}
                  </button>
                </div>
              </form>
            </section>
          )}
          {tab === "hardware" && (
            <section>
              <div className="section-heading">
                <h2>{t("hardwareTitle")}</h2>
                <p>{t("hardwareHint")}</p>
              </div>
              <div className="hardware-panel">
                <div>
                  <HardwareIndicator
                    state={hardwareState}
                    label={hardwareLabel}
                  />
                  <p className="muted">{t("hardwareDetectionHint")}</p>
                  <h3>{t("capability")}</h3>
                  <dl className="capabilities">
                    <div>
                      <dt>ssh</dt>
                      <dd>{t(caps?.ssh ? "available" : "unavailable")}</dd>
                    </div>
                    <div>
                      <dt>ssh-keygen</dt>
                      <dd>{t(caps?.keygen ? "available" : "unavailable")}</dd>
                    </div>
                    <div>
                      <dt>{t("supported")}</dt>
                      <dd>
                        {caps?.securityKeyAlgorithms.join(", ") ||
                          t("unavailable")}
                      </dd>
                    </div>
                  </dl>
                  <p className="muted">{t("deviceNote")}</p>
                  <button
                    className="primary"
                    onClick={() => {
                      chooseAlgorithm("ed25519-sk");
                      setTab("generate");
                    }}
                  >
                    {t("useHardware")}
                  </button>
                </div>
              </div>
              <div className="section-heading totp-heading">
                <h2>{t("totpTitle")}</h2>
                <p>{t("totpHint")}</p>
              </div>
              <ol className="totp-steps">
                {(
                  ["totp1", "totp2", "totp3", "totp4", "totp5"] as TextKey[]
                ).map((label, index) => (
                  <li key={label}>
                    <p>{t(label)}</p>
                    <pre>
                      {
                        [
                          "sudo apt install libpam-google-authenticator",
                          "google-authenticator",
                          "auth required pam_google_authenticator.so",
                          "UsePAM yes\nKbdInteractiveAuthentication yes\nAuthenticationMethods publickey,keyboard-interactive",
                          "sudo sshd -t\nsudo systemctl reload ssh",
                        ][index]
                      }
                    </pre>
                  </li>
                ))}
              </ol>
              <p className="alert">{t("totpWarning")}</p>
            </section>
          )}
          {tab === "servers" && (
            <section>
              <div className="section-heading">
                <h2>{t("serverTitle")}</h2>
                <p>{t("serverHint")}</p>
              </div>
              <div className="form-panel">
                <div className="form-grid">
                  <label>
                    {t("host")}
                    <input
                      placeholder="server.example.com"
                      value={server.host}
                      onChange={(event) => {
                        setSnippets(undefined);
                        setServer((old) => ({
                          ...old,
                          host: event.target.value,
                        }));
                      }}
                    />
                  </label>
                  <label>
                    {t("user")}
                    <input
                      value={server.user}
                      onChange={(event) => {
                        setSnippets(undefined);
                        setServer((old) => ({
                          ...old,
                          user: event.target.value,
                        }));
                      }}
                    />
                  </label>
                  <label>
                    {t("port")}
                    <input
                      type="number"
                      min="1"
                      max="65535"
                      value={server.port}
                      onChange={(event) => {
                        setSnippets(undefined);
                        setServer((old) => ({
                          ...old,
                          port: Number(event.target.value),
                        }));
                      }}
                    />
                  </label>
                  <label>
                    {t("selectedKey")}
                    <select
                      value={server.keyName}
                      onChange={(event) => {
                        setSnippets(undefined);
                        setServer((old) => ({
                          ...old,
                          keyName: event.target.value,
                        }));
                      }}
                    >
                      <option value="">—</option>
                      {scan.keys.map((item) => (
                        <option key={item.name}>{item.name}</option>
                      ))}
                    </select>
                  </label>
                </div>
                <div className="actions">
                  <button
                    className="primary"
                    disabled={busy || !api || !server.keyName}
                    onClick={() =>
                      void act(async () =>
                        setSnippets(await unwrap(api!.snippets(server))),
                      )
                    }
                  >
                    {t("commands")}
                  </button>
                  <button
                    disabled={busy || !api || !caps?.copyId || !server.keyName}
                    onClick={() =>
                      void act(() => unwrap(api!.deploy(server)), "deployed")
                    }
                  >
                    {t("deploy")}
                  </button>
                </div>
                {snippets && (
                  <>
                    <p className="muted">{t("manualNote")}</p>
                    {Object.entries(snippets).map(([shell, command]) => (
                      <div className="command" key={shell}>
                        <div>
                          <strong>
                            {shell === "powershell" ? "PowerShell" : "POSIX"}
                          </strong>
                          <button
                            data-copied={copiedAction === "shell:" + shell}
                            disabled={busy || !api}
                            onClick={() =>
                              void act(async () => {
                                await unwrap(
                                  api!.copySnippet(
                                    server,
                                    shell as "powershell" | "posix",
                                  ),
                                );
                                setCopiedAction("shell:" + shell);
                              })
                            }
                          >
                            {t(
                              copiedAction === "shell:" + shell
                                ? "copiedInline"
                                : "copyCommand",
                            )}
                          </button>
                        </div>
                        <pre>{command}</pre>
                      </div>
                    ))}
                  </>
                )}
              </div>
              <div className="section-heading config-heading">
                <h2>{t("configTitle")}</h2>
                <p>{t("configHint")}</p>
              </div>
              <div className="form-panel">
                <div className="host-tags">
                  {config?.hosts.length ? (
                    config.hosts.map((host, index) => (
                      <button
                        key={`${host.aliases}-${index}`}
                        onClick={() => setAlias(host.aliases.split(/\s+/)[0])}
                      >
                        {host.aliases}
                      </button>
                    ))
                  ) : (
                    <span className="muted">{t("noHosts")}</span>
                  )}
                </div>
                <div className="inline-form">
                  <label>
                    {t("alias")}
                    <input
                      value={alias}
                      onChange={(event) => setAlias(event.target.value)}
                    />
                  </label>
                  <button
                    disabled={busy || !api || !server.keyName}
                    onClick={() => void act(appendHost)}
                  >
                    {t("addHost")}
                  </button>
                  <button
                    disabled={busy || !api || !alias}
                    onClick={() =>
                      void act(async () =>
                        setResolved(await unwrap(api!.resolveHost(alias))),
                      )
                    }
                  >
                    {t("resolve")}
                  </button>
                </div>
                <p className="muted">{t("resolveHint")}</p>
                {resolved && <pre>{resolved}</pre>}
                <label>
                  {t("configTitle")}
                  <textarea
                    aria-label={t("configTitle")}
                    spellCheck={false}
                    rows={12}
                    placeholder={t("configPlaceholder")}
                    value={configText}
                    onChange={(event) => setConfigText(event.target.value)}
                  />
                </label>
                <div className="actions">
                  <button
                    className="primary"
                    disabled={busy || !api || !config}
                    onClick={() =>
                      void act(async () => {
                        const value = await unwrap(
                          api!.saveConfig(configText, config!.revision),
                        );
                        setConfig(value);
                        setConfigText(value.text);
                      }, "saved")
                    }
                  >
                    {t("save")}
                  </button>
                  <button
                    disabled={busy || !api}
                    onClick={() =>
                      void act(
                        () => unwrap(api!.validateConfig(configText)),
                        "valid",
                      )
                    }
                  >
                    {t("validate")}
                  </button>
                  <button
                    disabled={busy || !api}
                    onClick={() => void act(loadConfig)}
                  >
                    {t("resetConfig")}
                  </button>
                </div>
              </div>
            </section>
          )}
        </div>
      </main>
      {prompt && (
        <div className="modal-overlay">
          <form
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="prompt-title"
            onSubmit={(event) => {
              event.preventDefault();
              void api?.answerPrompt(prompt.id, answer).then((result) => {
                if (!result.ok) setError(result.error);
              });
              setAnswer("");
              setPrompt(undefined);
            }}
          >
            <h2 id="prompt-title">{t(prompt.kind)}</h2>
            <p>
              {t(
                prompt.kind === "hostkey"
                  ? "hostkeyHint"
                  : prompt.kind === "pin"
                    ? "sk"
                    : "passwordHint",
              )}
            </p>
            {prompt.fingerprint && <pre>{prompt.fingerprint}</pre>}
            {prompt.kind !== "hostkey" && (
              <input
                autoFocus
                aria-label={t(prompt.kind)}
                type="password"
                autoComplete="off"
                value={answer}
                onChange={(event) => setAnswer(event.target.value)}
              />
            )}
            <div className="actions">
              {prompt.kind === "hostkey" ? (
                <>
                  <button
                    type="button"
                    disabled={!prompt.fingerprint}
                    onClick={() => {
                      void api?.answerPrompt(prompt.id, "yes");
                      setPrompt(undefined);
                    }}
                  >
                    {t("trust")}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      void api?.answerPrompt(prompt.id, "no");
                      setPrompt(undefined);
                    }}
                  >
                    {t("reject")}
                  </button>
                </>
              ) : (
                <button className="primary">{t("answer")}</button>
              )}
              <button
                type="button"
                onClick={() => {
                  void api?.cancel();
                  setAnswer("");
                  setPrompt(undefined);
                }}
              >
                {t("cancel")}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>,
);
