import { describe, expect, it } from "vitest";
import { createAccount } from "./accounts";
import { findDeviceByPublicId, listDevices, registerDevice } from "./devices";
import { isValidDeviceId } from "../lib/ids";

describe("devices (integration)", () => {
  it("registerDevice дає валідний publicId і прив'язку до акаунта", async () => {
    const a = await createAccount("o@example.com", "h");
    const d = await registerDevice(a.id, { alias: "Домашній ПК" });
    expect(isValidDeviceId(d.publicId)).toBe(true);
    expect(d.accountId).toBe(a.id);
    expect(d.alias).toBe("Домашній ПК");
    expect((await findDeviceByPublicId(d.publicId))?.id).toBe(d.id);
  });

  it("ізоляція орендарів: акаунт бачить ЛИШЕ свої пристрої", async () => {
    const a = await createAccount("a@example.com", "h");
    const b = await createAccount("b@example.com", "h");
    await registerDevice(a.id);
    await registerDevice(a.id);
    await registerDevice(b.id);

    expect(await listDevices(a.id)).toHaveLength(2);
    expect(await listDevices(b.id)).toHaveLength(1);
  });

  it("publicId унікальний між пристроями", async () => {
    const a = await createAccount("u@example.com", "h");
    const d1 = await registerDevice(a.id);
    const d2 = await registerDevice(a.id);
    expect(d1.publicId).not.toBe(d2.publicId);
  });
});
