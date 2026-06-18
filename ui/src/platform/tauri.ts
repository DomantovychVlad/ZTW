import { invoke, Channel } from "@tauri-apps/api/core";
import type {
  ConnectOpts,
  HostOpts,
  HostStatus,
  InputEvent,
  Platform,
  SessionHandle,
} from "./index";

// Десктоп-реалізація: сесія крутиться у Rust-ядрі (core::connection) через Tauri IPC.
// Кадри H.264 приходять base64-рядком у Channel; ввід — командою send_input.
export function createDesktopPlatform(): Platform {
  return {
    kind: "desktop",
    describe: () => "Десктоп (Tauri): сесія крізь Rust-ядро, нативне крипто й канал.",

    async connect(opts: ConnectOpts): Promise<SessionHandle> {
      const onFrame = new Channel<string>();
      onFrame.onmessage = (b64: string) => {
        const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
        opts.onFrame(bin);
      };

      await invoke("connect", {
        server: opts.server,
        deviceId: opts.deviceId,
        clientSecret: opts.clientSecret,
        password: opts.password,
        passwordKind: opts.passwordKind,
        targetId: opts.targetId,
        onFrame,
      });

      return {
        sendInput: (ev: InputEvent) => {
          void invoke("send_input", { event: ev });
        },
        disconnect: () => {
          void invoke("disconnect");
        },
      };
    },

    async wake(opts) {
      return await invoke("wake_device", {
        server: opts.server,
        deviceId: opts.deviceId,
        clientSecret: opts.clientSecret,
        targetId: opts.targetId,
      });
    },

    async startHost(opts: HostOpts): Promise<void> {
      type HostUiEvent =
        | { type: "oneTime"; code: string }
        | { type: "confirm"; requestId: number; passwordKind: string };
      const onEvent = new Channel<HostUiEvent>();
      onEvent.onmessage = (ev: HostUiEvent) => {
        if (ev.type === "oneTime") opts.onOneTime(ev.code);
        else opts.onConfirm({ requestId: ev.requestId, passwordKind: ev.passwordKind });
      };
      await invoke("start_host", {
        server: opts.server,
        deviceId: opts.deviceId,
        clientSecret: opts.clientSecret,
        permanentPassword: opts.permanentPassword,
        confirmIncoming: opts.confirmIncoming,
        lockOnEnd: opts.lockOnEnd,
        onEvent,
      });
    },
    async stopHost(): Promise<void> {
      await invoke("stop_host");
    },
    async hostStatus(): Promise<HostStatus> {
      return await invoke<HostStatus>("host_status");
    },
    async refreshOneTime(): Promise<void> {
      await invoke("refresh_one_time");
    },
    async setConfirmIncoming(enabled: boolean): Promise<void> {
      await invoke("set_confirm_incoming", { enabled });
    },
    async setLockOnEnd(enabled: boolean): Promise<void> {
      await invoke("set_lock_on_end", { enabled });
    },
    async decideIncoming(requestId: number, allow: boolean): Promise<void> {
      await invoke("decide_incoming", { requestId, allow });
    },
    async setAutostart(enabled: boolean): Promise<void> {
      await invoke("set_autostart", { enabled });
    },
    async fsLocalList(path: string) {
      return await invoke<import("./index").FsListing>("fs_local_list", { path });
    },
    async fsDownload(remotePath: string, localPath: string): Promise<number> {
      return await invoke<number>("fs_download", { remotePath, localPath });
    },
    async fsUpload(localPath: string, remotePath: string): Promise<number> {
      return await invoke<number>("fs_upload", { localPath, remotePath });
    },
    async fsCancel(id: number): Promise<void> {
      await invoke("fs_cancel", { id });
    },
    async getAutostart(): Promise<boolean> {
      return await invoke<boolean>("get_autostart");
    },
    async appConfig() {
      return await invoke<{ portable: boolean; defaultServer?: string | null }>("app_config");
    },
  };
}
