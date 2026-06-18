import { describe, expect, it } from "vitest";
import { createAccount } from "./accounts";
import { registerDevice, listDevices } from "./devices";
import { assignDeviceGroup, createGroup, deleteGroup, listGroups, renameGroup } from "./groups";

describe("groups (integration)", () => {
  it("createGroup створює групу акаунта; дубль імені в межах акаунта -> null", async () => {
    const a = await createAccount("g1@example.com", "h");
    const g = await createGroup(a.id, "Дім");
    expect(g?.name).toBe("Дім");
    expect(g?.accountId).toBe(a.id);
    expect(await createGroup(a.id, "Дім")).toBeNull();
  });

  it("однакове ім'я в РІЗНИХ акаунтах дозволене", async () => {
    const a = await createAccount("g2a@example.com", "h");
    const b = await createAccount("g2b@example.com", "h");
    expect(await createGroup(a.id, "Робота")).not.toBeNull();
    expect(await createGroup(b.id, "Робота")).not.toBeNull();
  });

  it("ізоляція орендарів: listGroups бачить лише свої групи", async () => {
    const a = await createAccount("g3a@example.com", "h");
    const b = await createAccount("g3b@example.com", "h");
    await createGroup(a.id, "Дім");
    await createGroup(a.id, "Робота");
    await createGroup(b.id, "Клієнти");

    expect((await listGroups(a.id)).map((g) => g.name)).toEqual(["Дім", "Робота"]);
    expect((await listGroups(b.id)).map((g) => g.name)).toEqual(["Клієнти"]);
  });

  it("renameGroup: ok / not_found для чужої або неіснуючої / duplicate на зайняте ім'я", async () => {
    const a = await createAccount("g4a@example.com", "h");
    const b = await createAccount("g4b@example.com", "h");
    const g1 = (await createGroup(a.id, "Дім"))!;
    await createGroup(a.id, "Робота");

    expect(await renameGroup(a.id, g1.id, "Офіс")).toBe("ok");
    expect((await listGroups(a.id)).map((g) => g.name).sort()).toEqual(["Офіс", "Робота"]);
    // чужий акаунт не може перейменувати
    expect(await renameGroup(b.id, g1.id, "Хак")).toBe("not_found");
    expect(await renameGroup(a.id, "nope", "X")).toBe("not_found");
    // зайняте ім'я в межах акаунта
    expect(await renameGroup(a.id, g1.id, "Робота")).toBe("duplicate");
  });

  it("deleteGroup: видаляє свою, не видаляє чужу; пристрої лишаються без групи", async () => {
    const a = await createAccount("g5a@example.com", "h");
    const b = await createAccount("g5b@example.com", "h");
    const g = (await createGroup(a.id, "Дім"))!;
    const d = await registerDevice(a.id, { alias: "ПК" });
    expect(await assignDeviceGroup(a.id, d.publicId, g.id)).toBe("ok");

    expect(await deleteGroup(b.id, g.id)).toBe(false); // чужа — не видалилась
    expect(await deleteGroup(a.id, g.id)).toBe(true);

    const after = await listDevices(a.id);
    expect(after).toHaveLength(1); // пристрій живий
    expect(after[0].groupId).toBeNull(); // але вже без групи (SetNull)
  });

  it("assignDeviceGroup: призначення, зняття (null), чужа група/пристрій", async () => {
    const a = await createAccount("g6a@example.com", "h");
    const b = await createAccount("g6b@example.com", "h");
    const ga = (await createGroup(a.id, "Дім"))!;
    const gb = (await createGroup(b.id, "Дім"))!;
    const d = await registerDevice(a.id);

    expect(await assignDeviceGroup(a.id, d.publicId, ga.id)).toBe("ok");
    expect((await listDevices(a.id))[0].groupId).toBe(ga.id);

    // зняти з групи
    expect(await assignDeviceGroup(a.id, d.publicId, null)).toBe("ok");
    expect((await listDevices(a.id))[0].groupId).toBeNull();

    // ЧУЖА група — заборонено (інакше міжорендний витік через FK)
    expect(await assignDeviceGroup(a.id, d.publicId, gb.id)).toBe("group_not_found");
    // чужий пристрій — невидимий
    expect(await assignDeviceGroup(b.id, d.publicId, gb.id)).toBe("not_found");
  });
});
