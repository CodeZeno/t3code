import { describe, expect, it } from "vite-plus/test";
import { it as effectIt } from "@effect/vitest";
import { HostProcessArchitecture, HostProcessPlatform } from "@t3tools/shared/hostProcess";
import * as Effect from "effect/Effect";

import {
  collectProcessTreeIds,
  parseWindowsTcpTable,
  readWindowsProcessResources,
  readWindowsProcessTree,
} from "./WindowsNativeSystem.ts";

describe("WindowsNativeSystem", () => {
  it("collects only the requested process tree", () => {
    const ids = collectProcessTreeIds(
      [
        { pid: 10, ppid: 1, name: "server.exe" },
        { pid: 11, ppid: 10, name: "agent.exe" },
        { pid: 12, ppid: 11, name: "tool.exe" },
        { pid: 20, ppid: 1, name: "unrelated.exe" },
      ],
      10,
    );
    expect([...ids]).toEqual([10, 11, 12]);
  });

  it("parses local IPv4 listener rows and ignores non-local addresses", () => {
    const table = Buffer.alloc(4 + 2 * 24);
    table.writeUInt32LE(2, 0);
    table.writeUInt32LE(2, 4);
    table[8] = 127;
    table.writeUInt16BE(5173, 12);
    table.writeUInt32LE(1234, 24);
    const second = 28;
    table.writeUInt32LE(2, second);
    table[second + 4] = 192;
    table[second + 5] = 168;
    table.writeUInt16BE(8080, second + 8);
    table.writeUInt32LE(5678, second + 20);

    expect(parseWindowsTcpTable(table, 2)).toEqual([{ port: 5173, pid: 1234 }]);
  });

  effectIt("reads the current process without creating a helper process on Windows", () =>
    Effect.gen(function* () {
      if ((yield* HostProcessPlatform) !== "win32") return;
      const architecture = yield* HostProcessArchitecture;
      const tree = readWindowsProcessTree(architecture);
      expect(tree.some((row) => row.pid === process.pid)).toBe(true);
      const resources = readWindowsProcessResources(process.pid, architecture);
      const current = resources.find((row) => row.pid === process.pid);
      expect(current).toBeDefined();
      expect(current?.command.length).toBeGreaterThan(0);
      expect(current?.rssBytes).toBeGreaterThan(0);
    }),
  );
});
