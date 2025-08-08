const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const win = std.os.windows;

const W = std.unicode.utf8ToUtf16LeStringLiteral;

const Aes256 = std.crypto.core.aes.Aes256;
const AesEnc = std.crypto.core.aes.AesEncryptCtx(Aes256);

const tSetEvent = *const fn (win.HANDLE) callconv(.C) win.BOOL;
var pSetEvent: ?tSetEvent = null;

pub const GuardedEncAllocator = struct {
    // Public: expose a std.mem.Allocator
    allocator: std.mem.Allocator = undefined,

    // Settings
    decrypt_timeout_ms: u32 = 750, // how long a page stays decrypted after touch
    use_parent: bool = false,

    // If use_parent == true
    parent: ?std.mem.Allocator = null,

    // Global state
    mu: std.Thread.Mutex = .{},
    regions: std.AutoHashMap(*align(4096) u8, *Region),
    page_size: usize,

    // crypto
    enc: AesEnc,
    salt: [8]u8,

    // async helper
    recrypt_thread: ?std.Thread = null,
    wake_event: ?win.HANDLE = null,
    quit: bool = false,

    // Windows stuff
    veh_cookie: ?win.PVOID = null,
    SetEvent: tSetEvent,

    const Self = @This();

    const PageState = enum(u1) { Enc, Dec };
    const PageInfo = packed struct {
        state: PageState,
        // future: can put last_decrypt_tsc etc
    };

    const Region = struct {
        base: *align(4096) u8,
        size: usize, // requested size
        cap: usize, // rounded pages
        page_count: usize,
        page_tbl: []PageInfo, // one per page
        timeout_ms: u32,

        // scheduling: a single deadline for “next recrypt scan”
        // (simple but effective; we re-encrypt all Dec pages whose grace passed)
        next_deadline_ns: i128,
    };

    fn allocFn(ctx: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
        _ = ret_addr;
        var self: *Self = @ptrCast(@alignCast(ctx));
        return self.allocImpl(len, alignment);
    }

    fn resizeFn(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = ret_addr;
        var self: *Self = @ptrCast(@alignCast(ctx));
        return self.resizeImpl(buf, alignment, new_len);
    }

    fn freeFn(ctx: *anyopaque, buf: []u8, alignment: mem.Alignment, ret_addr: usize) void {
        _ = ret_addr;
        var self: *Self = @ptrCast(@alignCast(ctx));
        self.freeImpl(buf, alignment);
    }

    fn remapFn(
        ctx: *anyopaque,
        buf: []u8,
        alignment: mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ctx;
        _ = buf;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return null; // signal "cannot remap"
    }
    pub fn init(allocator: std.mem.Allocator, use_parent: bool, parent_opt: ?std.mem.Allocator) !*Self {
        if (pSetEvent == null) {
            const kernel32: win.HMODULE = win.kernel32.GetModuleHandleW(W("kernel32.dll")) orelse unreachable;
            const fSetEvent: tSetEvent = @ptrCast(win.kernel32.GetProcAddress(kernel32, "SetEvent") orelse unreachable);
            pSetEvent = fSetEvent;
        }

        if (use_parent and parent_opt == null)
            return error.MissingParent;

        var key: [32]u8 = undefined;
        std.crypto.random.bytes(@as([*]u8, @ptrCast(&key))[0..32]);

        var salt: [8]u8 = undefined;
        std.crypto.random.bytes(&salt);

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = .{
                .ptr = undefined, // set below
                .vtable = &.{
                    .alloc = allocFn,
                    .resize = resizeFn,
                    .free = freeFn,
                    .remap = remapFn,
                },
            },
            .decrypt_timeout_ms = 750,
            .use_parent = use_parent,
            .parent = parent_opt,
            .mu = .{},
            .regions = std.AutoHashMap(*align(4096) u8, *Region).init(allocator),
            .page_size = std.heap.page_size_min,
            .enc = Aes256.initEnc(key),
            .salt = salt,
            .recrypt_thread = null,
            .wake_event = null,
            .quit = false,
            .veh_cookie = null,
            .SetEvent = pSetEvent.?,
        };

        self.allocator.ptr = @ptrCast(self);

        try self.installVeh();

        self.wake_event = try win.CreateEventExW(null, null, 0, win.EVENT_ALL_ACCESS);
        if (self.wake_event == null) return error.WinCreateEvent;

        self.recrypt_thread = try std.Thread.spawn(.{}, recryptWorker, .{self});

        return self;
    }

    pub fn deinit(self: *Self) void {
        // stop worker
        self.mu.lock();
        self.quit = true;
        const evt = self.wake_event;
        self.mu.unlock();
        if (evt) |h| {
            _ = self.SetEvent(h);
        }
        if (self.recrypt_thread) |t| t.join();
        if (evt) |h| _ = win.CloseHandle(h);

        // remove VEH
        if (self.veh_cookie) |c| {
            _ = win.kernel32.RemoveVectoredExceptionHandler(c);
        }

        // free regions
        var it = self.regions.valueIterator();
        while (it.next()) |pr| {
            const r = pr.*;
            self.osUnmap(r.base, r.cap);
            self.freeRegionStruct(r);
        }
        self.regions.deinit();
    }

    pub fn setDecryptTimeoutMs(self: *Self, ms: u32) void {
        self.mu.lock();
        defer self.mu.unlock();
        self.decrypt_timeout_ms = ms;
    }

    fn pagesFor(self: *Self, n: usize) usize {
        return (n + self.page_size - 1) / self.page_size;
    }

    fn roundCap(self: *Self, n: usize) usize {
        return self.pagesFor(n) * self.page_size;
    }

    fn allocImpl(self: *Self, len: usize, alignment: mem.Alignment) ?[*]u8 {

        // We guarantee page alignment for guarded operation.
        if (len == 0) return null;

        const want_align = @max(alignment.toByteUnits(), self.page_size);
        _ = want_align;

        const cap = self.roundCap(len);
        const base = self.osMap(cap) orelse return null;

        var region = self.allocRegionStruct() catch {
            self.osUnmap(base, cap);
            return null;
        };
        region.* = .{
            .base = base,
            .size = len,
            .cap = cap,
            .page_count = cap / self.page_size,
            .page_tbl = undefined,
            .timeout_ms = self.decrypt_timeout_ms,
            .next_deadline_ns = 0,
        };

        // page table
        region.page_tbl = self.regionAllocSlice(PageInfo, region.page_count) catch {
            self.osUnmap(base, cap);
            self.freeRegionStruct(region);
            return null;
        };
        for (region.page_tbl) |*p| p.* = .{ .state = .Enc };

        self.encryptRange(@as([*]u8, @ptrCast(base)), cap);

        _ = self.protect(base, cap, win.PAGE_NOACCESS) catch {
            self.regionFreeSlice(region.page_tbl);
            self.osUnmap(base, cap);
            self.freeRegionStruct(region);
            return null;
        };

        self.mu.lock();
        defer self.mu.unlock();
        self.regions.put(base, region) catch return null;

        if (builtin.mode == .Debug) {
            var mbi: win.MEMORY_BASIC_INFORMATION = undefined;
            const got = win.kernel32.VirtualQuery(@as(*anyopaque, @ptrCast(base)), &mbi, @sizeOf(@TypeOf(mbi)));
            if (got != 0) {
                std.debug.assert(mbi.Protect == win.PAGE_NOACCESS);
            }
        }

        return @as([*]u8, @ptrCast(base));
    }

    fn resizeImpl(self: *Self, buf: []u8, alignment: mem.Alignment, new_len: usize) bool {
        _ = self;
        _ = alignment;

        // We do not support in-place grow/shrink safely (page tables, protections).
        // Return false to force caller to alloc-copy-free.
        _ = buf;
        _ = new_len;
        return false;
    }

    fn freeImpl(self: *Self, buf: []u8, alignment: mem.Alignment) void {
        _ = alignment;
        if (buf.len == 0) return;

        const base = @as(*align(4096) u8, @ptrCast(@alignCast(buf.ptr)));
        self.mu.lock();
        const fr = self.regions.fetchRemove(base);
        self.mu.unlock();

        if (fr) |entry| {
            const region = entry.value;

            // Always make it writable so we can encrypt one last pass
            _ = self.protect(region.base, region.cap, win.PAGE_READWRITE) catch {};
            self.encryptRange(@as([*]u8, @ptrCast(region.base)), region.cap); // last pass

            // Only keep NOACCESS if we’re going to VirtualFree; for parent.free we must stay RW.
            if (!self.use_parent) {
                _ = self.protect(region.base, region.cap, win.PAGE_NOACCESS) catch {};
            }

            self.regionFreeSlice(region.page_tbl);
            self.osUnmap(region.base, region.cap);
            self.freeRegionStruct(region);
        }
    }

    fn installVeh(self: *Self) !void {
        const cookie = win.kernel32.AddVectoredExceptionHandler(1, vehThunk);
        if (cookie == null) return error.VehInstallFailed;
        self.veh_cookie = cookie;
        // register self in TLS so thunk can find us
        VEH_STATE.register(self);
    }

    const VEH_STATE = struct {
        var mu: std.Thread.Mutex = .{};
        var inst: ?*Self = null;

        pub fn register(s: *Self) void {
            mu.lock();
            inst = s;
            mu.unlock();
        }
        pub fn get() ?*Self {
            mu.lock();
            defer mu.unlock();
            return inst;
        }
    };

    fn vehThunk(rec: *win.EXCEPTION_POINTERS) callconv(.C) win.LONG {
        const opt = VEH_STATE.get();
        if (opt == null) return 0;

        var self = opt.?;
        const er = rec.ExceptionRecord.*;
        if (er.ExceptionCode != win.EXCEPTION_ACCESS_VIOLATION) {
            return 0;
        }

        if (er.NumberParameters < 2) return win.EXCEPTION_CONTINUE_SEARCH;
        const addr = @as([*]u8, @ptrFromInt(er.ExceptionInformation[1]));

        return self.onGuardFault(addr);
    }

    fn onGuardFault(self: *Self, fault_addr: [*]u8) win.LONG {
        // Determine if fault falls within one of our regions
        self.mu.lock();
        var hit_region: ?*Region = null;
        var base_ptr: ?*align(4096) u8 = null;

        var it = self.regions.iterator();
        while (it.next()) |kv| {
            const base = kv.key_ptr.*;
            const r = kv.value_ptr.*;
            if (@intFromPtr(fault_addr) >= @intFromPtr(base) and
                @intFromPtr(fault_addr) < @intFromPtr(base) + r.cap)
            {
                hit_region = r;
                base_ptr = base;
                break;
            }
        }

        if (hit_region == null) {
            self.mu.unlock();
            return 0;
        }

        const r = hit_region.?;
        const base = base_ptr.?;

        // compute page index
        const off = @intFromPtr(fault_addr) - @intFromPtr(base);
        const page_idx = off / self.page_size;
        self.mu.unlock();

        // decrypt page and flip to RW
        const page_base: *align(4096) u8 = @ptrFromInt(@intFromPtr(base) + page_idx * self.page_size);

        if (self.protect(page_base, self.page_size, win.PAGE_READWRITE)) |_| {
            self.decryptRange(@as([*]u8, @ptrCast(page_base)), self.page_size);

            // mark page state
            self.mu.lock();
            r.page_tbl[page_idx].state = .Dec;
            r.next_deadline_ns = std.time.nanoTimestamp() + @as(i128, @intCast(self.decrypt_timeout_ms)) * std.time.ns_per_ms;
            self.mu.unlock();

            // signal worker to schedule re-encrypt
            if (self.wake_event) |h| {
                _ = self.SetEvent(h);
            }
            return -1;
        } else |_| {
            return 0;
        }
    }

    // ------------------------ re-encrypt worker -----------------------------
    fn recryptWorker(self: *Self) !void {
        while (true) {
            // Wait up to timeout or wake signal
            var wait_ms: u32 = 1000;

            self.mu.lock();
            if (self.quit) {
                self.mu.unlock();
                break;
            }

            // compute earliest deadline
            var earliest: ?i128 = null;
            var it = self.regions.valueIterator();
            while (it.next()) |pr| {
                const r = pr.*;
                if (r.next_deadline_ns != 0) {
                    if (earliest == null or r.next_deadline_ns < earliest.?)
                        earliest = r.next_deadline_ns;
                }
            }

            if (earliest) |t_ns| {
                const now = std.time.nanoTimestamp();
                if (t_ns > now) {
                    const delta_ns: i128 = t_ns - now;
                    wait_ms = @intCast(@max(@as(i128, 1), @divFloor(delta_ns, std.time.ns_per_ms)));
                } else {
                    wait_ms = 1;
                }
            }
            const evt = self.wake_event;
            self.mu.unlock();
            if (evt) |h| {
                const s = win.kernel32.WaitForSingleObject(h, wait_ms);
                if (s != win.WAIT_OBJECT_0 and s != win.WAIT_TIMEOUT) {
                    // WAIT_FAILED or unexpected: just continue, don’t crash
                }
                // On both signal and timeout we drop to the scan below.
            } else {
                std.time.sleep(@as(u64, wait_ms) * std.time.ns_per_ms);
            }
            self.reencryptScan();
        }
    }

    fn reencryptScan(self: *Self) void {
        const now = std.time.nanoTimestamp();

        self.mu.lock();
        defer self.mu.unlock();

        var it = self.regions.valueIterator();
        while (it.next()) |pr| {
            const r = pr.*;
            if (r.next_deadline_ns == 0 or r.next_deadline_ns > now) continue;

            // Re-encrypt all pages marked Dec, flip to NOACCESS
            var i: usize = 0;
            while (i < r.page_count) : (i += 1) {
                if (r.page_tbl[i].state == .Dec) {
                    const p: *align(4096) u8 = @ptrFromInt(@intFromPtr(r.base) + i * self.page_size);

                    _ = self.protect(p, self.page_size, win.PAGE_READWRITE) catch unreachable;
                    self.encryptRange(@as([*]u8, @ptrCast(p)), self.page_size);
                    _ = self.protect(p, self.page_size, win.PAGE_NOACCESS) catch unreachable;

                    r.page_tbl[i].state = .Enc;
                }
            }
            r.next_deadline_ns = 0;
        }
    }

    // --------------------------- crypto -------------------------------------
    fn xorKeystream(self: *Self, data: []u8, nonce64: u64) void {
        var block: [16]u8 = undefined;
        var ks: [16]u8 = undefined;

        var off: usize = 0;
        var ctr: u64 = 0;

        while (off < data.len) : (ctr += 1) {
            @memcpy(block[0..8], self.salt[0..8]);
            std.mem.writeInt(u64, block[8..16], nonce64 ^ ctr, .little);

            self.enc.encrypt(&ks, &block);

            const take = @min(@as(usize, 16), data.len - off);
            var i: usize = 0;
            while (i < take) : (i += 1) {
                data[off + i] ^= ks[i];
            }
            off += take;
        }
    }

    fn pageNonce(self: *Self, base: *align(4096) u8, page_index: usize) u64 {
        const ps: usize = self.page_size;
        const page_num: u64 = @intCast(@intFromPtr(base) / ps);
        return page_num ^ @as(u64, @intCast(page_index));
    }
    fn pageNumFromAddr(self: *Self, page_aligned_addr: usize) u64 {
        return @intCast(page_aligned_addr / self.page_size);
    }

    fn nonceFromPageNum(self: *Self, page_num: u64) u64 {
        _ = self;
        // simple and stable; salt already goes into the AES block.
        return page_num;
    }

    fn encryptRange(self: *Self, p: [*]u8, len: usize) void {
        const ps = self.page_size;

        const p_single: *u8 = @ptrCast(p);
        const p_addr: usize = @intFromPtr(p_single);
        const base_addr: usize = p_addr & ~(ps - 1);
        const page_off: usize = (p_addr - base_addr) / ps;

        var remaining = len;
        var idx: usize = 0;

        while (remaining != 0) : (idx += 1) {
            const take = @min(ps, remaining);
            const page_addr = base_addr + (page_off + idx) * ps;
            const page_num = self.pageNumFromAddr(page_addr);
            const nonce = self.nonceFromPageNum(page_num);

            const start = idx * ps;
            self.xorKeystream(p[start .. start + take], nonce);

            remaining -= take;
        }
    }
    fn decryptRange(self: *Self, p: [*]u8, len: usize) void {
        self.encryptRange(p, len);
    }

    fn osMap(self: *Self, cap: usize) ?*align(4096) u8 {
        if (builtin.os.tag != .windows) return null;

        if (!self.use_parent) {
            const ptr = win.VirtualAlloc(null, cap, win.MEM_COMMIT | win.MEM_RESERVE, win.PAGE_READWRITE) catch {
                return null;
            };
            return @ptrCast(@alignCast(ptr));
        } else {
            const memory = self.parent.?.alloc(u8, cap) catch return null;
            return @as(*align(4096) u8, @ptrCast(@alignCast(memory.ptr)));
        }
    }

    fn osUnmap(self: *Self, base: *align(4096) u8, cap: usize) void {
        if (!self.use_parent) {
            _ = win.VirtualFree(base, 0, win.MEM_RELEASE);
        } else {
            // Parent allocator will memset; memory must be RW already.
            self.parent.?.free(@as([*]u8, @ptrCast(base))[0..cap]);
        }
    }

    fn protect(self: *Self, p: *anyopaque, len: usize, prot: win.DWORD) !void {
        _ = self;
        var old: win.DWORD = 0;
        win.VirtualProtect(p, len, prot, &old) catch {
            return error.VirtualProtectFailed;
        };
    }

    fn allocRegionStruct(self: *Self) !*Region {
        return try self.regions.allocator.create(Region);
    }
    fn freeRegionStruct(self: *Self, r: *Region) void {
        self.regions.allocator.destroy(r);
    }
    fn regionAllocSlice(self: *Self, comptime T: type, n: usize) ![]T {
        return try self.regions.allocator.alloc(T, n);
    }
    fn regionFreeSlice(self: *Self, s: anytype) void {
        self.regions.allocator.free(s);
    }
};
