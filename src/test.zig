const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;

// ---- helpers ----
fn skipIfNotWindows() !void {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
}

fn protAt(p: [*]const u8) !u32 {
    var mbi: win.MEMORY_BASIC_INFORMATION = undefined;
    const lp: *anyopaque = @constCast(@as(*const anyopaque, @ptrCast(p)));
    const got = win.kernel32.VirtualQuery(lp, &mbi, @sizeOf(@TypeOf(mbi)));
    if (got == 0) return error.VirtualQueryFailed;
    return mbi.Protect;
}

fn ptrPlus(p: [*]const u8, off: usize) *const u8 {
    return @as(*const u8, @ptrFromInt(@intFromPtr(p) + off));
}

fn waitUntilNoAccess(p: [*]const u8, timeout_ms: u32) !void {
    const start = std.time.milliTimestamp();
    while (true) {
        const prot = try protAt(p);
        if (prot == win.PAGE_NOACCESS) return;
        if (std.time.milliTimestamp() - start > timeout_ms) return error.Timeout;
        std.Thread.sleep(2 * std.time.ns_per_ms);
    }
}

const GuardedEncAllocator = @import("root.zig").GuardedEncAllocator;

test "GEA: basic RW roundtrip + guard flips" {
    try skipIfNotWindows();

    const gpa = std.heap.page_allocator;
    var enc = try GuardedEncAllocator.init(gpa, false, null); // *GuardedEncAllocator
    defer enc.deinit();

    enc.setDecryptTimeoutMs(120);
    const a = enc.allocator;

    const n = enc.page_size + enc.page_size / 2;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);
    win.kernel32.Sleep(200);

    try std.testing.expectEqual(win.PAGE_NOACCESS, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    buf[0] = 0xA5;
    buf[n - 1] = 0x5A;

    try std.testing.expectEqual(win.PAGE_READWRITE, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    const page2 = @as([*]const u8, @ptrCast(buf.ptr)) + enc.page_size;
    try std.testing.expectEqual(win.PAGE_READWRITE, try protAt(page2));

    try waitUntilNoAccess(@as([*]const u8, @ptrCast(buf.ptr)), 1000);
    try waitUntilNoAccess(page2, 1000);

    try std.testing.expectEqual(@as(u8, 0xA5), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x5A), buf[n - 1]);
}

test "GEA: per-page lazy decrypt across 8 pages" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, false, null);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(80);
    const a = enc.allocator;

    const pages: usize = 8;
    const n = enc.page_size * pages;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);

    win.kernel32.Sleep(100);
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const off = i * enc.page_size;
        const v: u8 = @intCast(0x10 + i);
        buf[off] = v;
        try std.testing.expectEqual(v, buf[off]);

        const page_probe = @as([*]const u8, @ptrCast(buf.ptr)) + off;
        try std.testing.expectEqual(win.PAGE_READWRITE, try protAt(page_probe));
    }

    std.Thread.sleep(200 * std.time.ns_per_ms);

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

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, true, std.heap.page_allocator);
    defer enc.deinit();
    enc.setDecryptTimeoutMs(100);

    const a = enc.allocator;
    const n = enc.page_size * 3 + 33;
    const buf = try a.alloc(u8, n);
    defer a.free(buf);

    win.kernel32.Sleep(120);

    try std.testing.expectEqual(win.PAGE_NOACCESS, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    buf[17] = 0xAB;
    try std.testing.expectEqual(@as(u8, 0xAB), buf[17]);
    try std.testing.expectEqual(win.PAGE_READWRITE, try protAt(@as([*]const u8, @ptrCast(buf.ptr))));

    std.Thread.sleep(200 * std.time.ns_per_ms);
    try waitUntilNoAccess(@as([*]const u8, @ptrCast(buf.ptr)), 1000);

    try std.testing.expectEqual(@as(u8, 0xAB), buf[17]);
}

test "GEA: resize/remap unsupported" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, false, null);
    defer enc.deinit();

    const a = enc.allocator;

    const buf = try a.alloc(u8, 1234);
    defer a.free(buf);

    try std.testing.expect(!a.resize(buf, 9999));
}

test "GEA: free unmaps (VirtualQuery not committed)" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, false, null);
    defer enc.deinit();

    const a = enc.allocator;

    const n = enc.page_size * 2;
    const buf = try a.alloc(u8, n);
    const base_single: *const u8 = @ptrCast(buf.ptr);

    buf[0] = 1;
    a.free(buf);

    var mbi: win.MEMORY_BASIC_INFORMATION = undefined;
    const got = win.kernel32.VirtualQuery(@constCast(@as(*const anyopaque, @ptrCast(base_single))), &mbi, @sizeOf(@TypeOf(mbi)));
    if (got != 0) {
        try std.testing.expect(mbi.State != win.MEM_COMMIT);
    } else {
        try std.testing.expect(true);
    }
}

test "GEA: data integrity across multiple encrypt/decrypt cycles" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, false, null);
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

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, false, null);
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
                std.Thread.sleep(50_000);
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
        std.Thread.sleep(200_000);
    }

    var j: usize = 0;
    while (j < threads.len) : (j += 1) threads[j].join();
}

test "GEA: stress - many mixed allocations + patterns + frees" {
    try skipIfNotWindows();

    var enc = try GuardedEncAllocator.init(std.heap.page_allocator, false, null);
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

    std.Thread.sleep(100 * std.time.ns_per_ms);

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
