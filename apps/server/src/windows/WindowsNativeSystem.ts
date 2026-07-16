/**
 * Lightweight Windows process and TCP listener inspection via Win32 APIs.
 *
 * This module intentionally avoids PowerShell, WMI, and performance-counter
 * classes. Process topology comes from Toolhelp32, resource counters come from
 * GetProcessTimes/GetProcessMemoryInfo, and listeners come from
 * GetExtendedTcpTable. The DLLs are loaded once and stay resident until the
 * server exits; no worker process or background task is created here.
 */
import { DataType, isNullPointer, load, open, type JsExternal } from "ffi-rs";

const KERNEL32_LIBRARY = "t3-windows-kernel32";
const NTDLL_LIBRARY = "t3-windows-ntdll";
const IPHLPAPI_LIBRARY = "t3-windows-iphlpapi";

const TH32CS_SNAPPROCESS = 0x00000002;
const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const TCP_TABLE_OWNER_PID_LISTENER = 3;
const AF_INET = 2;
const AF_INET6 = 23;
const ERROR_INSUFFICIENT_BUFFER = 122;
const PROCESS_COMMAND_LINE_INFORMATION = 60;
const WINDOWS_FILETIME_EPOCH_OFFSET_100NS = 116_444_736_000_000_000n;
const MIN_CPU_SAMPLE_INTERVAL_NS = 250_000_000n;
const MAX_COMMAND_LINE_BYTES = 64 * 1024;
const MAX_PROCESS_IMAGE_CHARS = 32_768;

const PROCESS_ENTRY_PID_OFFSET = 8;

interface CpuSample {
  readonly creationTime100ns: bigint;
  readonly cpuTime100ns: bigint;
  readonly sampledAtNs: bigint;
  readonly cpuPercent: number;
}

export interface WindowsProcessTreeEntry {
  readonly pid: number;
  readonly ppid: number;
  readonly name: string;
}

export interface WindowsProcessResourceEntry extends WindowsProcessTreeEntry {
  readonly command: string;
  readonly cpuPercent: number;
  readonly rssBytes: number;
  readonly elapsed: string;
}

export interface WindowsTcpListener {
  readonly port: number;
  readonly pid: number;
}

let librariesOpened = false;
const previousCpuSamples = new Map<number, CpuSample>();

function ensureLibraries(): void {
  if (librariesOpened) return;
  open({ library: KERNEL32_LIBRARY, path: "kernel32.dll" });
  open({ library: NTDLL_LIBRARY, path: "ntdll.dll" });
  open({ library: IPHLPAPI_LIBRARY, path: "iphlpapi.dll" });
  librariesOpened = true;
}

function closeHandle(handle: JsExternal): void {
  load({
    library: KERNEL32_LIBRARY,
    funcName: "CloseHandle",
    retType: DataType.Boolean,
    paramsType: [DataType.External],
    paramsValue: [handle],
  });
}

function readNullTerminatedUtf16(buffer: Buffer, offset: number): string {
  let end = offset;
  while (end + 1 < buffer.length && buffer.readUInt16LE(end) !== 0) end += 2;
  return buffer.toString("utf16le", offset, end).trim();
}

export function readWindowsProcessTree(
  architecture: NodeJS.Architecture,
): ReadonlyArray<WindowsProcessTreeEntry> {
  ensureLibraries();
  const processEntrySize = architecture === "ia32" ? 556 : 568;
  const processEntryPpidOffset = architecture === "ia32" ? 24 : 32;
  const processEntryNameOffset = architecture === "ia32" ? 36 : 44;
  const snapshot = load({
    library: KERNEL32_LIBRARY,
    funcName: "CreateToolhelp32Snapshot",
    retType: DataType.External,
    paramsType: [DataType.U32, DataType.U32],
    paramsValue: [TH32CS_SNAPPROCESS, 0],
  });

  const entry = Buffer.alloc(processEntrySize);
  entry.writeUInt32LE(processEntrySize, 0);
  const rows: WindowsProcessTreeEntry[] = [];

  try {
    let hasEntry = load({
      library: KERNEL32_LIBRARY,
      funcName: "Process32FirstW",
      retType: DataType.Boolean,
      paramsType: [DataType.External, DataType.U8Array],
      paramsValue: [snapshot, entry],
    });

    while (hasEntry) {
      const pid = entry.readUInt32LE(PROCESS_ENTRY_PID_OFFSET);
      const ppid = entry.readUInt32LE(processEntryPpidOffset);
      const name = readNullTerminatedUtf16(entry, processEntryNameOffset);
      if (pid > 0 && name.length > 0) rows.push({ pid, ppid, name });

      entry.fill(0);
      entry.writeUInt32LE(processEntrySize, 0);
      hasEntry = load({
        library: KERNEL32_LIBRARY,
        funcName: "Process32NextW",
        retType: DataType.Boolean,
        paramsType: [DataType.External, DataType.U8Array],
        paramsValue: [snapshot, entry],
      });
    }
  } finally {
    closeHandle(snapshot);
  }

  return rows;
}

export function collectProcessTreeIds(
  rows: ReadonlyArray<WindowsProcessTreeEntry>,
  rootPid: number,
): ReadonlySet<number> {
  const childrenByParent = new Map<number, number[]>();
  for (const row of rows) {
    const children = childrenByParent.get(row.ppid) ?? [];
    children.push(row.pid);
    childrenByParent.set(row.ppid, children);
  }

  const processIds = new Set<number>();
  const pending = [rootPid];
  while (pending.length > 0) {
    const pid = pending.pop();
    if (pid === undefined || processIds.has(pid)) continue;
    processIds.add(pid);
    pending.push(...(childrenByParent.get(pid) ?? []));
  }
  return processIds;
}

function openProcess(pid: number): JsExternal | null {
  const handle = load({
    library: KERNEL32_LIBRARY,
    funcName: "OpenProcess",
    retType: DataType.External,
    paramsType: [DataType.U32, DataType.Boolean, DataType.U32],
    paramsValue: [PROCESS_QUERY_LIMITED_INFORMATION, false, pid],
  });
  return isNullPointer(handle) ? null : handle;
}

function readProcessCommandLine(
  handle: JsExternal,
  fallback: string,
  architecture: NodeJS.Architecture,
): string {
  const buffer = Buffer.alloc(MAX_COMMAND_LINE_BYTES);
  const returnLength = Buffer.alloc(4);
  const status = load({
    library: NTDLL_LIBRARY,
    funcName: "NtQueryInformationProcess",
    retType: DataType.I32,
    paramsType: [DataType.External, DataType.U32, DataType.U8Array, DataType.U32, DataType.U8Array],
    paramsValue: [handle, PROCESS_COMMAND_LINE_INFORMATION, buffer, buffer.length, returnLength],
  });
  if (status === 0) {
    const byteLength = buffer.readUInt16LE(0);
    const stringOffset = architecture === "ia32" ? 8 : 16;
    if (byteLength > 0 && stringOffset + byteLength <= buffer.length) {
      const command = buffer.toString("utf16le", stringOffset, stringOffset + byteLength).trim();
      if (command.length > 0) return command;
    }
  }

  const image = Buffer.alloc(MAX_PROCESS_IMAGE_CHARS * 2);
  const imageLength = Buffer.alloc(4);
  imageLength.writeUInt32LE(MAX_PROCESS_IMAGE_CHARS, 0);
  const readImage = load({
    library: KERNEL32_LIBRARY,
    funcName: "QueryFullProcessImageNameW",
    retType: DataType.Boolean,
    paramsType: [DataType.External, DataType.U32, DataType.U8Array, DataType.U8Array],
    paramsValue: [handle, 0, image, imageLength],
  });
  return readImage
    ? image.toString("utf16le", 0, imageLength.readUInt32LE(0) * 2).trim() || fallback
    : fallback;
}

function formatElapsed(creationTime100ns: bigint): string {
  const nowMs = Math.floor(performance.timeOrigin + performance.now());
  const now100ns = BigInt(nowMs) * 10_000n + WINDOWS_FILETIME_EPOCH_OFFSET_100NS;
  const elapsedSeconds = Number((now100ns - creationTime100ns) / 10_000_000n);
  if (!Number.isFinite(elapsedSeconds) || elapsedSeconds < 0) return "n/a";
  const seconds = Math.floor(elapsedSeconds % 60);
  const minutes = Math.floor((elapsedSeconds / 60) % 60);
  const hours = Math.floor(elapsedSeconds / 3_600);
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, "0")).join(":");
}

function readProcessResources(
  handle: JsExternal,
  pid: number,
  sampledAtNs: bigint,
): Omit<WindowsProcessResourceEntry, "pid" | "ppid" | "name" | "command"> | null {
  const creation = Buffer.alloc(8);
  const exit = Buffer.alloc(8);
  const kernel = Buffer.alloc(8);
  const user = Buffer.alloc(8);
  const readTimes = load({
    library: KERNEL32_LIBRARY,
    funcName: "GetProcessTimes",
    retType: DataType.Boolean,
    paramsType: [
      DataType.External,
      DataType.U8Array,
      DataType.U8Array,
      DataType.U8Array,
      DataType.U8Array,
    ],
    paramsValue: [handle, creation, exit, kernel, user],
  });
  if (!readTimes) return null;

  const memory = Buffer.alloc(80);
  memory.writeUInt32LE(memory.length, 0);
  const readMemory = load({
    library: KERNEL32_LIBRARY,
    funcName: "K32GetProcessMemoryInfo",
    retType: DataType.Boolean,
    paramsType: [DataType.External, DataType.U8Array, DataType.U32],
    paramsValue: [handle, memory, memory.length],
  });

  const creationTime100ns = creation.readBigUInt64LE(0);
  const cpuTime100ns = kernel.readBigUInt64LE(0) + user.readBigUInt64LE(0);
  const previous = previousCpuSamples.get(pid);
  let cpuPercent = previous?.cpuPercent ?? 0;
  if (
    previous?.creationTime100ns === creationTime100ns &&
    sampledAtNs - previous.sampledAtNs >= MIN_CPU_SAMPLE_INTERVAL_NS
  ) {
    const elapsed100ns = (sampledAtNs - previous.sampledAtNs) / 100n;
    const used100ns = cpuTime100ns - previous.cpuTime100ns;
    cpuPercent =
      elapsed100ns > 0n && used100ns >= 0n
        ? Math.max(0, (Number(used100ns) / Number(elapsed100ns)) * 100)
        : 0;
  }
  if (!previous || sampledAtNs - previous.sampledAtNs >= MIN_CPU_SAMPLE_INTERVAL_NS) {
    previousCpuSamples.set(pid, {
      creationTime100ns,
      cpuTime100ns,
      sampledAtNs,
      cpuPercent,
    });
  }

  return {
    cpuPercent,
    rssBytes: readMemory ? Number(memory.readBigUInt64LE(16)) : 0,
    elapsed: formatElapsed(creationTime100ns),
  };
}

export function readWindowsProcessResources(
  rootPid: number,
  architecture: NodeJS.Architecture,
): ReadonlyArray<WindowsProcessResourceEntry> {
  const tree = readWindowsProcessTree(architecture);
  const targetIds = collectProcessTreeIds(tree, rootPid);
  const sampledAtNs = process.hrtime.bigint();
  const result: WindowsProcessResourceEntry[] = [];

  for (const row of tree) {
    if (!targetIds.has(row.pid)) continue;
    const handle = openProcess(row.pid);
    if (handle === null) continue;
    try {
      const resources = readProcessResources(handle, row.pid, sampledAtNs);
      if (resources === null) continue;
      result.push({
        ...row,
        command: readProcessCommandLine(handle, row.name, architecture),
        ...resources,
      });
    } finally {
      closeHandle(handle);
    }
  }

  const liveIds = new Set(tree.map((row) => row.pid));
  for (const pid of previousCpuSamples.keys()) {
    if (!liveIds.has(pid)) previousCpuSamples.delete(pid);
  }
  return result;
}

function isLocalIpv4Row(buffer: Buffer, offset: number): boolean {
  return buffer.readUInt32LE(offset + 4) === 0 || buffer[offset + 4] === 127;
}

function isLocalIpv6Row(buffer: Buffer, offset: number): boolean {
  const address = buffer.subarray(offset, offset + 16);
  const allZero = address.every((byte) => byte === 0);
  const loopback = address.subarray(0, 15).every((byte) => byte === 0) && address[15] === 1;
  return allZero || loopback;
}

export function parseWindowsTcpTable(
  buffer: Buffer,
  addressFamily: typeof AF_INET | typeof AF_INET6,
): ReadonlyArray<WindowsTcpListener> {
  const rowSize = addressFamily === AF_INET ? 24 : 56;
  const count = buffer.length >= 4 ? buffer.readUInt32LE(0) : 0;
  const listeners: WindowsTcpListener[] = [];
  for (let index = 0; index < count; index += 1) {
    const offset = 4 + index * rowSize;
    if (offset + rowSize > buffer.length) break;
    const local =
      addressFamily === AF_INET ? isLocalIpv4Row(buffer, offset) : isLocalIpv6Row(buffer, offset);
    if (!local) continue;
    const portOffset = addressFamily === AF_INET ? offset + 8 : offset + 20;
    const pidOffset = addressFamily === AF_INET ? offset + 20 : offset + 52;
    const port = buffer.readUInt16BE(portOffset);
    const pid = buffer.readUInt32LE(pidOffset);
    if (port > 0 && pid > 0) listeners.push({ port, pid });
  }
  return listeners;
}

function readTcpTable(
  addressFamily: typeof AF_INET | typeof AF_INET6,
): ReadonlyArray<WindowsTcpListener> {
  const size = Buffer.alloc(4);
  const firstResult = load({
    library: IPHLPAPI_LIBRARY,
    funcName: "GetExtendedTcpTable",
    retType: DataType.U32,
    paramsType: [
      DataType.U64,
      DataType.U8Array,
      DataType.Boolean,
      DataType.U32,
      DataType.U32,
      DataType.U32,
    ],
    paramsValue: [0, size, true, addressFamily, TCP_TABLE_OWNER_PID_LISTENER, 0],
  });
  if (firstResult !== ERROR_INSUFFICIENT_BUFFER) return [];

  const table = Buffer.alloc(size.readUInt32LE(0));
  const result = load({
    library: IPHLPAPI_LIBRARY,
    funcName: "GetExtendedTcpTable",
    retType: DataType.U32,
    paramsType: [
      DataType.U8Array,
      DataType.U8Array,
      DataType.Boolean,
      DataType.U32,
      DataType.U32,
      DataType.U32,
    ],
    paramsValue: [table, size, true, addressFamily, TCP_TABLE_OWNER_PID_LISTENER, 0],
  });
  if (result !== 0) throw new Error(`GetExtendedTcpTable failed with Windows error ${result}.`);
  return parseWindowsTcpTable(table, addressFamily);
}

export function readWindowsTcpListeners(): ReadonlyArray<WindowsTcpListener> {
  ensureLibraries();
  const seen = new Set<string>();
  return [...readTcpTable(AF_INET), ...readTcpTable(AF_INET6)].filter((listener) => {
    const key = `${listener.port}:${listener.pid}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
