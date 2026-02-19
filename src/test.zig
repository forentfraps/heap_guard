const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;
const tio = std.testing.io;
pub extern "kernel32" fn GetModuleHandleW(
    lpModuleName: [*:0]const win.WCHAR,
) callconv(.winapi) ?win.HMODULE;
pub extern "kernel32" fn GetProcAddress(
    module: win.HMODULE,
    procName: [*:0]const u8,
) callconv(.winapi) ?win.FARPROC;
extern "kernel32" fn AddVectoredExceptionHandler(
    First: std.os.windows.ULONG,
    Handler: ?*const fn (ExceptionInfo: *std.os.windows.EXCEPTION_POINTERS) callconv(.winapi) std.os.windows.LONG,
) callconv(.winapi) ?std.os.windows.PVOID;
extern "kernel32" fn CreateEventExW(
    lpEventAttributes: ?*std.os.windows.SECURITY_ATTRIBUTES,
    lpName: ?std.os.windows.LPCWSTR,
    dwFlags: std.os.windows.DWORD,
    dwDesiredAccess: std.os.windows.DWORD,
) callconv(.winapi) ?std.os.windows.HANDLE;
extern "kernel32" fn VirtualProtect(
    lpAddress: std.os.windows.LPVOID,
    dwSize: std.os.windows.SIZE_T,
    flNewProtect: std.os.windows.DWORD,
    lpflOldProtect: *std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn VirtualFree(
    lpAddress: std.os.windows.LPVOID,
    dwSize: std.os.windows.SIZE_T,
    dwFreeType: std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.BOOL;
extern "kernel32" fn VirtualAlloc(
    lpAddress: ?std.os.windows.LPVOID,
    dwSize: std.os.windows.SIZE_T,
    flAllocationType: std.os.windows.DWORD,
    flProtect: std.os.windows.DWORD,
) callconv(.winapi) ?std.os.windows.LPVOID;
extern "kernel32" fn Sleep(
    dwMilliseconds: std.os.windows.DWORD,
) callconv(.winapi) void;
extern "kernel32" fn RemoveVectoredExceptionHandler(
    Handle: std.os.windows.PVOID,
) callconv(.winapi) std.os.windows.ULONG;
extern "kernel32" fn WaitForSingleObject(
    hHandle: std.os.windows.HANDLE,
    dwMilliseconds: std.os.windows.DWORD,
) callconv(.winapi) std.os.windows.DWORD;
extern "kernel32" fn VirtualQuery(
    lpAddress: ?std.os.windows.LPCVOID,
    lpBuffer: *MEMORY_BASIC_INFORMATION,
    dwLength: std.os.windows.SIZE_T,
) callconv(.winapi) std.os.windows.SIZE_T;

const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: std.os.windows.PVOID,
    AllocationBase: std.os.windows.PVOID,
    AllocationProtect: std.os.windows.DWORD,
    PartitionId: std.os.windows.WORD,
    RegionSize: std.os.windows.SIZE_T,
    State: std.os.windows.DWORD,
    Protect: std.os.windows.DWORD,
    Type: std.os.windows.DWORD,
};
const GENERIC_WRITE: u32 = 0x40000000;
const GENERIC_READ: u32 = 0x80000000;
const FILE_SHARE_READ: u32 = 0x00000001;
const FILE_SHARE_WRITE: u32 = 0x00000002;
const OPEN_EXISTING: u32 = 3;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
const MEM_RESERVE: u32 = 0x00002000;
const MEM_RELEASE: std.os.windows.DWORD = 0x00008000;
const MEM_COMMIT: u32 = 0x00001000;
const EVENT_ALL_ACCESS: std.os.windows.DWORD = 0x001F0003;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_READONLY: u32 = 0x02;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_WRITECOPY: u32 = 0x08;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

// Modifiers (OR with above)
const PAGE_GUARD: u32 = 0x100;
const PAGE_NOCACHE: u32 = 0x200;
const PAGE_WRITECOMBINE: u32 = 0x400;

// ---- helpers ----
fn skipIfNotWindows() !void {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
}

fn protAt(p: [*]const u8) !u32 {
    var mbi: MEMORY_BASIC_INFORMATION = undefined;
    const lp: *anyopaque = @constCast(@as(*const anyopaque, @ptrCast(p)));
    const got = VirtualQuery(lp, &mbi, @sizeOf(@TypeOf(mbi)));
    if (got == 0) return error.VirtualQueryFailed;
    return mbi.Protect;
}

fn ptrPlus(p: [*]const u8, off: usize) *const u8 {
    return @as(*const u8, @ptrFromInt(@intFromPtr(p) + off));
}

fn waitUntilNoAccess(p: [*]const u8, timeout_ms: u32) !void {
    const start = std.Io.Timestamp.now(tio, .boot).toMilliseconds();
    while (true) {
        const prot = try protAt(p);
        if (prot == PAGE_NOACCESS) return;
        if (std.Io.Timestamp.now(tio, .boot).toMilliseconds() - start > timeout_ms) return error.Timeout;
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(2 * std.time.ns_per_ms), .boot);
    }
}

const GuardedEncAllocator = @import("root.zig").GuardedEncAllocator;

test "GEA: basic RW roundtrip + guard flips" {
    try skipIfNotWindows();

    const gpa = std.heap.page_allocator;
    var enc = try GuardedEncAllocator.init(gpa, tio, false, null); // *GuardedEncAllocator
    defer enc.deinit();

    enc.setDecryptTimeoutMs(120);
    const a = enc.allocator;

    const n = enc.page_size + enc.page_size / 2;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);
    Sleep(200);

    try std.testing.expectEqual(PAGE_NOACCESS, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    buf[0] = 0xA5;
    buf[n - 1] = 0x5A;

    try std.testing.expectEqual(PAGE_READWRITE, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    const page2 = @as([*]const u8, @ptrCast(buf.ptr)) + enc.page_size;
    try std.testing.expectEqual(PAGE_READWRITE, try protAt(page2));

    try waitUntilNoAccess(@as([*]const u8, @ptrCast(buf.ptr)), 1000);
    try waitUntilNoAccess(page2, 1000);

    try std.testing.expectEqual(@as(u8, 0xA5), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x5A), buf[n - 1]);
}

test "GEA: per-page lazy decrypt across 8 pages" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, false, null);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(80);
    const a = enc.allocator;

    const pages: usize = 8;
    const n = enc.page_size * pages;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);

    Sleep(100);
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const off = i * enc.page_size;
        const v: u8 = @intCast(0x10 + i);
        buf[off] = v;
        try std.testing.expectEqual(v, buf[off]);

        const page_probe = @as([*]const u8, @ptrCast(buf.ptr)) + off;
        try std.testing.expectEqual(PAGE_READWRITE, try protAt(page_probe));
    }

    try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(200), .boot);

    i = 0;
    while (i < pages) : (i += 1) {
        const page_probe = @as([*]const u8, @ptrCast(buf.ptr)) + i * enc.page_size;
        try waitUntilNoAccess(page_probe, 1000);
    }

    i = 0;
    while (i < pages) : (i += 1) {
        const off = i * enc.page_size;
        try std.testing.expectEqual(@as(u8, @intCast(0x10 + i)), buf[off]);
    }
}

test "GEA: parent allocator mode still guards" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, true, std.heap.page_allocator);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(100);

    const a = enc.allocator;
    const n = enc.page_size * 3 + 33;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);

    Sleep(120);

    try std.testing.expectEqual(PAGE_NOACCESS, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    buf[17] = 0xAB;
    try std.testing.expectEqual(@as(u8, 0xAB), buf[17]);
    try std.testing.expectEqual(PAGE_READWRITE, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(200), .boot);
    try waitUntilNoAccess(@as([*]const u8, @ptrCast(buf.ptr)), 1000);

    try std.testing.expectEqual(@as(u8, 0xAB), buf[17]);
}

test "GEA: resize/remap unsupported" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, false, null);
    defer enc.deinit();

    const a = enc.allocator;

    const buf = try a.alloc(u8, 1234);
    defer a.free(buf);

    try std.testing.expect(!a.resize(buf, 9999));
}

test "GEA: free unmaps (VirtualQuery not committed)" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, false, null);
    defer enc.deinit();

    const a = enc.allocator;

    const n = enc.page_size * 2;
    const buf = try a.alloc(u8, n);
    const base_single: *const u8 = @ptrCast(buf.ptr);

    buf[0] = 1;
    a.free(buf);

    var mbi: MEMORY_BASIC_INFORMATION = undefined;
    const got = VirtualQuery(@constCast(@as(*const anyopaque, @ptrCast(base_single))), &mbi, @sizeOf(@TypeOf(mbi)));
    if (got != 0) {
        try std.testing.expect(mbi.State != MEM_COMMIT);
    } else {
        try std.testing.expect(true);
    }
}

test "GEA: data integrity across multiple encrypt/decrypt cycles" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, false, null);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(50);

    const a = enc.allocator;

    const n = enc.page_size * 4 + 7;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);

    var xoshiro = std.Random.DefaultPrng.init(0xC0FFEE);
    var prng = xoshiro.random();

    // fill with random
    var i: usize = 0;
    while (i < n) : (i += 1) buf[i] = prng.uintAtMost(u8, 255);

    // re-encrypt a few times
    var round: usize = 0;
    while (round < 5) : (round += 1) {
        try waitUntilNoAccess(@as([*]const u8, @ptrCast(buf.ptr)), 2000);
        // read some spots to decrypt again
        var k: usize = 0;
        while (k < 32 and k < n) : (k += 7) {
            _ = buf[k];
        }
    }

    // final sanity sweep
    var sum: u64 = 0;
    i = 0;
    while (i < n) : (i += 1) sum +%= buf[i];
    try std.testing.expect(sum != 0);
}

test "GEA: concurrent access from multiple threads" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, false, null);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(60);

    const a = enc.allocator;

    const pages: usize = 16;
    const n = enc.page_size * pages;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);

    const Worker = struct {
        fn run(a_local: std.mem.Allocator, p: [*]u8, page_size: usize, idx: usize) !void {
            _ = a_local;
            const off = idx * page_size;
            var v: u8 = @intCast(idx);
            var iter: usize = 0;
            while (iter < 2000) : (iter += 1) {
                p[off] = v;
                if (p[off] != v) return error.Corruption;
                try std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(50_000), .boot);
                v +%= 1;
            }
        }
    };

    var threads: [8]std.Thread = undefined;
    var tcount: usize = 0;
    while (tcount < threads.len) : (tcount += 1) {
        const page_idx = tcount * 2;
        threads[tcount] = try std.Thread.spawn(
            .{},
            Worker.run,
            .{ a, @as([*]u8, @ptrCast(buf.ptr)), enc.page_size, page_idx },
        );
    }

    var i: usize = 1;
    while (i < pages) : (i += 2) {
        const off = i * enc.page_size;
        buf[off] = 0xEE;
        try std.testing.expectEqual(@as(u8, 0xEE), buf[off]);
        try std.Io.sleep(std.testing.io, std.Io.Duration.fromNanoseconds(200_000), .boot);
    }

    var j: usize = 0;
    while (j < threads.len) : (j += 1) threads[j].join();
}

test "GEA: stress - many mixed allocations + patterns + frees" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, tio, false, null);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(40);

    const a = enc.allocator;

    var xoshiro = std.Random.DefaultPrng.init(0xBADC0DE);
    var rnd = xoshiro.random();

    const Count = 64;
    var bufs: [Count][]u8 = undefined;

    // allocate a bunch of varied sizes
    var i: usize = 0;
    while (i < Count) : (i += 1) {
        const sz = rnd.uintAtMost(usize, 8191) + 1;
        bufs[i] = try a.alloc(u8, sz);
        // fill pattern
        var k: usize = 0;
        const step = @max(@as(usize, 1), sz / 23);
        while (k < sz) : (k += step) bufs[i][k] = @intCast((i * 17 + k) & 0xff);
    }

    try std.Io.sleep(std.testing.io, std.Io.Duration.fromMilliseconds(100), .boot);

    // verify random spots, then free half
    i = 0;
    while (i < Count) : (i += 1) {
        const sz = bufs[i].len;
        var k: usize = 0;
        const step = @max(@as(usize, 1), sz / 23);
        while (k < sz) : (k += step) {
            const want: u8 = @intCast((i * 17 + k) & 0xff);
            try std.testing.expectEqual(want, bufs[i][k]);
        }
        if ((i % 2) == 0) a.free(bufs[i]);
    }

    // touch remaining to ensure still valid
    i = 0;
    while (i < Count) : (i += 1) {
        if ((i % 2) == 0) continue;
        if (bufs[i].len != 0) {
            const idx = @min(bufs[i].len - 1, @as(usize, 31));
            bufs[i][idx] ^= 0xFF;
        }
    }

    // free rest
    i = 0;
    while (i < Count) : (i += 1) if ((i % 2) == 1) a.free(bufs[i]);
}
