import { describe, expect, it } from "vitest";
import type { Connection } from "./registry";
import { Registry } from "./registry";
import type { ServerMessage } from "./protocol";

class MockConn implements Connection {
  sent: ServerMessage[] = [];
  closed = false;
  closeReason?: string;
  send(m: ServerMessage): void {
    this.sent.push(m);
  }
  close(reason?: string): void {
    this.closed = true;
    this.closeReason = reason;
  }
  ofType(t: ServerMessage["type"]): ServerMessage[] {
    return this.sent.filter((m) => m.type === t);
  }
}

function fixedIds() {
  let n = 0;
  return () => `s${++n}`;
}

describe("Registry — присутність", () => {
  it("online/isOnline/offline (host-слот)", () => {
    const r = new Registry();
    expect(r.isOnline("100000001")).toBe(false);
    r.online("100000001", "host", new MockConn());
    expect(r.isOnline("100000001")).toBe(true);
    r.offline("100000001", "host");
    expect(r.isOnline("100000001")).toBe(false);
  });

  it("лише controller-роль = НЕ online (підключитись нема до чого)", () => {
    const r = new Registry();
    r.online("100000001", "controller", new MockConn());
    expect(r.isOnline("100000001")).toBe(false);
    expect(r.presence(["100000001"])).toEqual([{ id: "100000001", online: false }]);
  });

  it("presence повертає online/offline і busy за host-слотом", () => {
    const r = new Registry({ makeSessionId: fixedIds() });
    r.online("200000002", "host", new MockConn());
    const p = r.presence(["200000002", "300000003"]);
    expect(p).toEqual([
      { id: "200000002", online: true, lastSeen: expect.any(Number), busy: false },
      { id: "300000003", online: false },
    ]);
  });

  it("повторний register тієї ж ролі закриває старе з'єднання", () => {
    const r = new Registry();
    const oldConn = new MockConn();
    r.online("100000001", "host", oldConn);
    r.online("100000001", "host", new MockConn());
    expect(oldConn.closed).toBe(true);
    expect(oldConn.closeReason).toBe("replaced");
  });

  it("host і controller на ОДНОМУ ID співіснують: реєстрація пульта не вибиває host", () => {
    const r = new Registry();
    const host = new MockConn();
    const ctrl = new MockConn();
    r.online("100000001", "host", host);
    r.online("100000001", "controller", ctrl);
    expect(host.closed).toBe(false); // host-слот не зачеплено
    expect(r.isOnline("100000001")).toBe(true);
    // Відпадання controller-слота лишає host онлайн.
    r.offline("100000001", "controller");
    expect(r.isOnline("100000001")).toBe(true);
    // А host-слота — знімає присутність.
    r.offline("100000001", "host");
    expect(r.isOnline("100000001")).toBe(false);
  });

  it("offline із conn-захистом: закриття ЗАМІНЕНОГО сокета не чіпає нову реєстрацію", () => {
    const r = new Registry();
    const oldConn = new MockConn();
    const newConn = new MockConn();
    r.online("100000001", "host", oldConn);
    r.online("100000001", "host", newConn); // replace
    r.offline("100000001", "host", oldConn); // запізніле close старого WS
    expect(r.isOnline("100000001")).toBe(true); // нова реєстрація жива
    r.offline("100000001", "host", newConn);
    expect(r.isOnline("100000001")).toBe(false);
  });
});

describe("Registry — потік підключення", () => {
  it("connect до офлайн-цілі -> offline (уніфіковано)", () => {
    const r = new Registry();
    r.online("100000001", "controller", new MockConn());
    expect(r.requestConnect("100000001", "controller", "999999999")).toEqual({
      ok: false,
      code: "offline",
    });
  });

  it("успішний connect_request -> incoming_request керованому з passwordKind", () => {
    const r = new Registry({ makeSessionId: fixedIds() });
    const ctrl = new MockConn();
    const host = new MockConn();
    r.online("100000001", "controller", ctrl);
    r.online("200000002", "host", host);

    const res = r.requestConnect("100000001", "controller", "200000002", "one_time");
    expect(res).toEqual({ ok: true, sessionId: "s1" });
    const inc = host.ofType("incoming_request");
    expect(inc).toHaveLength(1);
    expect(inc[0]).toMatchObject({
      type: "incoming_request",
      sessionId: "s1",
      passwordKind: "one_time",
    });
    expect(ctrl.sent).toHaveLength(0); // пульт ще нічого не отримує
  });

  it("busy за перевищення ліміту вхідних", () => {
    const r = new Registry({ makeSessionId: fixedIds(), maxInboundPerHost: 1 });
    r.online("100000001", "controller", new MockConn());
    r.online("100000009", "controller", new MockConn());
    r.online("200000002", "host", new MockConn());
    expect(r.requestConnect("100000001", "controller", "200000002").ok).toBe(true);
    expect(r.requestConnect("100000009", "controller", "200000002")).toEqual({
      ok: false,
      code: "busy",
    });
  });

  it("accept -> connect_ready обом, ролі коректні", () => {
    const r = new Registry({ makeSessionId: fixedIds() });
    const ctrl = new MockConn();
    const host = new MockConn();
    r.online("100000001", "controller", ctrl);
    r.online("200000002", "host", host);
    r.requestConnect("100000001", "controller", "200000002");

    expect(r.acceptConnect("s1", "200000002", "host")).toBe(true);
    const hostReady = host.ofType("connect_ready")[0];
    const ctrlReady = ctrl.ofType("connect_ready")[0];
    expect(hostReady).toMatchObject({ role: "offerer" }); // керований = ініціатор
    expect(ctrlReady).toMatchObject({ role: "answerer" }); // пульт = відповідач
  });

  it("accept чужим пристроєм або не-host-роллю відхиляється", () => {
    const r = new Registry({ makeSessionId: fixedIds() });
    r.online("100000001", "controller", new MockConn());
    r.online("200000002", "host", new MockConn());
    r.requestConnect("100000001", "controller", "200000002");
    expect(r.acceptConnect("s1", "100000001", "controller")).toBe(false); // не керований
    expect(r.acceptConnect("s1", "200000002", "controller")).toBe(false); // не host-роль
  });

  it("self-сесія: машина керує САМА СОБОЮ (controllerId === hostId), маршрутизація за роллю", () => {
    const r = new Registry({ makeSessionId: fixedIds() });
    const host = new MockConn();
    const ctrl = new MockConn();
    r.online("100000001", "host", host);
    r.online("100000001", "controller", ctrl);

    expect(r.requestConnect("100000001", "controller", "100000001").ok).toBe(true);
    expect(host.ofType("incoming_request")).toHaveLength(1);
    expect(ctrl.ofType("incoming_request")).toHaveLength(0); // НЕ продубльовано пульту

    expect(r.acceptConnect("s1", "100000001", "host")).toBe(true);
    expect(host.ofType("connect_ready")[0]).toMatchObject({ role: "offerer" });
    expect(ctrl.ofType("connect_ready")[0]).toMatchObject({ role: "answerer" });

    // Сигнал від host-ролі йде controller-слоту й навпаки.
    host.sent.length = 0;
    ctrl.sent.length = 0;
    expect(r.relaySignal("s1", "100000001", "host", "offer", { sdp: "x" })).toBe(true);
    expect(ctrl.ofType("signal")).toHaveLength(1);
    expect(host.sent).toHaveLength(0);
    expect(r.relaySignal("s1", "100000001", "controller", "answer", { sdp: "y" })).toBe(true);
    expect(host.ofType("signal")).toHaveLength(1);
  });
});

describe("Registry — Wake-on-LAN (крос-тенант ізоляція)", () => {
  it("помічник того ж акаунта в тій самій мережі будить ціль", () => {
    const r = new Registry();
    const helper = new MockConn();
    r.online("200000002", "host", helper, { wanIp: "1.2.3.4", canWake: true, accountId: "acc-A" });
    const res = r.dispatchWake("100000001", "AA:BB", "1.2.3.4", "acc-A");
    expect(res).toEqual({ status: "dispatched", helpers: 1 });
    expect(helper.ofType("wake_dispatch")[0]).toMatchObject({ mac: "AA:BB" });
    expect(r.helpersOnNetwork("1.2.3.4", "100000001", "acc-A")).toBe(1);
  });

  it("пристрій ЧУЖОГО акаунта в тій самій мережі помічником НЕ стає", () => {
    const r = new Registry();
    const intruder = new MockConn();
    r.online("200000002", "host", intruder, { wanIp: "1.2.3.4", canWake: true, accountId: "acc-B" });
    const res = r.dispatchWake("100000001", "AA:BB", "1.2.3.4", "acc-A");
    expect(res).toEqual({ status: "no_helper", helpers: 0 });
    expect(intruder.ofType("wake_dispatch")).toHaveLength(0);
    expect(r.helpersOnNetwork("1.2.3.4", "100000001", "acc-A")).toBe(0);
  });

  it("без MAC -> unsupported; невідомий акаунт цілі -> no_helper", () => {
    const r = new Registry();
    r.online("200000002", "host", new MockConn(), { wanIp: "1.2.3.4", canWake: true, accountId: "acc-A" });
    expect(r.dispatchWake("100000001", null, "1.2.3.4", "acc-A").status).toBe("unsupported");
    expect(r.dispatchWake("100000001", "AA:BB", "1.2.3.4", null).status).toBe("no_helper");
  });
});

describe("Registry — сліпий релей", () => {
  function ready() {
    const r = new Registry({ makeSessionId: fixedIds() });
    const ctrl = new MockConn();
    const host = new MockConn();
    r.online("100000001", "controller", ctrl);
    r.online("200000002", "host", host);
    r.requestConnect("100000001", "controller", "200000002");
    r.acceptConnect("s1", "200000002", "host");
    ctrl.sent.length = 0;
    host.sent.length = 0;
    return { r, ctrl, host };
  }

  it("offer від керованого йде ЛИШЕ пульту, payload непрозоро незмінний", () => {
    const { r, ctrl, host } = ready();
    const payload = { sdp: "v=0...opaque...", nested: { x: 1 } };
    expect(r.relaySignal("s1", "200000002", "host", "offer", payload)).toBe(true);
    expect(host.sent).toHaveLength(0); // відправнику не дублюється
    expect(ctrl.ofType("signal")[0]).toMatchObject({ type: "signal", kind: "offer", payload });
  });

  it("ice від пульта йде керованому", () => {
    const { r, ctrl, host } = ready();
    expect(r.relaySignal("s1", "100000001", "controller", "ice", { candidate: "x" })).toBe(true);
    expect(ctrl.sent).toHaveLength(0);
    expect(host.ofType("signal")[0]).toMatchObject({ kind: "ice" });
  });

  it("сигнал від не-члена сесії ігнорується", () => {
    const { r } = ready();
    const intruder = new MockConn();
    r.online("300000003", "controller", intruder);
    expect(r.relaySignal("s1", "300000003", "controller", "offer", { x: 1 })).toBe(false);
  });

  it("offline host-ролі розриває сесію й сповіщає піра", () => {
    const { r, ctrl, host } = ready();
    r.offline("200000002", "host"); // керований відпав
    expect(ctrl.ofType("session_close")[0]).toMatchObject({ type: "session_close", sessionId: "s1" });
    expect(host.ofType("session_close")).toHaveLength(0); // ініціатору не шлемо
  });
});
