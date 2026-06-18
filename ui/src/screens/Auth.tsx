import { useState } from "react";
import { api, type AccountInfo } from "../api";
import { Field } from "../widgets";

export function Auth(props: {
  server: string;
  setServer: (s: string) => void;
  platformKind: string;
  onAuthed: (a: AccountInfo) => Promise<void> | void;
}) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [totpNeeded, setTotpNeeded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setBusy(true);
    setErr("");
    try {
      const a =
        mode === "login"
          ? await api.login(props.server, email, password, totp.trim() || undefined)
          : await api.register(props.server, email, password);
      await props.onAuthed(a);
    } catch (e) {
      const msg = (e as Error).message;
      if (msg === "totp_required") {
        setTotpNeeded(true);
        setErr("На акаунті ввімкнено 2FA — введіть код із застосунку-автентифікатора");
      } else if (msg === "totp_invalid") {
        setTotpNeeded(true);
        setErr("Хибний код 2FA — спробуйте ще раз");
      } else {
        setErr(msg);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="connect-wrap">
      <div className="card">
        <h1 className="brand">ZortilWatch</h1>
        <p className="tagline">
          {mode === "login" ? "Вхід в акаунт" : "Створення акаунта"} · {props.platformKind}
        </p>
        <Field label="Сервер" value={props.server} onChange={props.setServer} />
        <Field label="E-mail" value={email} onChange={setEmail} type="email" />
        <Field label="Пароль" value={password} onChange={setPassword} type="password" />
        {mode === "login" && totpNeeded && (
          <Field label="Код 2FA (6 цифр)" value={totp} onChange={setTotp} placeholder="123 456" />
        )}
        <button className="btn btn-primary" onClick={submit} disabled={busy}>
          {busy ? "…" : mode === "login" ? "Увійти" : "Зареєструватися"}
        </button>
        {err && <p className="status err">{err}</p>}
        <p
          className="link"
          onClick={() => {
            setErr("");
            setMode((m) => (m === "login" ? "register" : "login"));
          }}
        >
          {mode === "login" ? "Немає акаунта? Зареєструватися" : "Уже є акаунт? Увійти"}
        </p>
      </div>
    </div>
  );
}
