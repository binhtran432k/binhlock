const std = @import("std");
const builtin = @import("builtin");

const config = @import("config.zig");
const Color = config.Color;

const c = @cImport({
    @cInclude("crypt.h");
    @cInclude("grp.h");
    @cInclude("pwd.h");
    @cInclude("string.h");
});

const x11 = @cImport({
    @cInclude("X11/extensions/Xrandr.h");
    @cInclude("X11/Xlib.h");
    @cInclude("X11/X.h");
});

const VERSION = c.VERSION;

const Lock = struct {
    screen: c_int,
    root: x11.Window,
    win: x11.Window,
    pmap: x11.Pixmap,
    colors: [config.NumCols]c_ulong,
};

const Xrandr = struct {
    active: c_int,
    evbase: c_int,
    errbase: c_int,
};

fn die(comptime fmt: []const u8, args: anytype) void {
    std.log.err(fmt, args);
    std.os.exit(1);
}

fn usage(status: u8) void {
    const msg = "usage: binhlock [-v | -h] [cmd [arg ...]]\n";
    if (status != 0) std.log.err(msg, .{}) else std.log.info(msg, .{});
    std.os.exit(status);
}

fn version() void {
    std.log.info("binhlock-{s}\n", .{VERSION});
    std.os.exit(0);
}

fn dontkillme(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .linux)
        return;

    const cLinux = @cImport({
        @cInclude("fcntl.h");
        @cInclude("linux/oom.h");
    });

    const oomfile = "/proc/self/oom_score_adj";
    if (std.fs.openFileAbsolute(oomfile, .{ .mode = .write_only })) |f| {
        const msg = try std.fmt.allocPrint(allocator, "{d}", .{cLinux.OOM_SCORE_ADJ_MIN});
        defer allocator.free(msg);
        _ = f.write(msg) catch {
            die("binklock: unable to disable OOM killer. Make sure to suid or sgid binhlock.\n", .{});
        };
    } else |err| {
        die("binhlock: std.fs.openFileAbsolute {s}: {s}\n", .{ oomfile, @errorName(err) });
    }
}

fn gethash() [*:0]u8 {
    // Check if the current user has a password entry
    const pw_ptr = c.getpwuid(std.os.linux.getuid());
    if (pw_ptr == null) {
        const errno = std.os.errno(-1);
        if (errno != .SUCCESS)
            die("binhlock: getpwuid: {s}\n", .{@tagName(errno)})
        else
            die("binhlock: cannot retrieve password entry\n", .{});
    }
    var hash_cstr = pw_ptr.*.pw_passwd;
    const hash_len = c.strlen(hash_cstr);
    if (@hasDecl(c, "HAVE_SHADOW_H")) {
        const cShadow = @cImport({
            @cInclude("shadow.h");
        });
        if (hash_len == 1 and hash_cstr[0] == 'x') {
            const sp_ptr = cShadow.getspnam(pw_ptr.*.pw_name);
            if (sp_ptr == null) {
                die("binhlock: getspnam: cannot retrieve shadow entry. Make sure to suid or sgid binhlock.\n", .{});
            }
            hash_cstr = sp_ptr.*.sp_pwdp;
        }
    } else {
        if (hash_len == 1 and hash_cstr[0] == '*') {
            if (builtin.os.tag == .freebsd) {
                const sp_ptr = c.getpwuid_shadow(c.getuid());
                if (sp_ptr == null) {
                    die("binhlock: getpwnam_shadow: cannot retrieve shadow entry. Make sure to suid or sgid binhlock.\n", .{});
                }
                hash_cstr = sp_ptr.*.pw_passwd;
            } else {
                die("binhlock: getpwuid: cannot retrieve shadow entry. Make sure to suid or sgid binhlock.\n", .{});
            }
        }
    }

    return hash_cstr;
}

fn readpw(dpy: ?*x11.Display, rr: *Xrandr, locks: []Lock, nscreens: c_int, hash: [*:0]u8) void {
    var running = true;
    var rre: *x11.XRRScreenChangeNotifyEvent = undefined;
    var ksym: x11.KeySym = undefined;
    var ev: x11.XEvent = undefined;
    var buf: [32:0]u8 = undefined;
    var passwd: [256:0]u8 = undefined;
    var len: c_int = 0;
    var failure: c_int = 0;
    var oldc: Color = Color.Init;

    while (running and x11.XNextEvent(dpy, &ev) == 0) {
        if (ev.type == x11.KeyPress) {
            c.explicit_bzero(&buf, @sizeOf(@TypeOf(buf)));
            const num = x11.XLookupString(&ev.xkey, &buf, @sizeOf(@TypeOf(buf)), &ksym, 0);
            if (x11.IsKeypadKey(ksym)) {
                if (ksym == x11.XK_KP_Enter) {
                    ksym = x11.XK_Return;
                } else if (ksym >= x11.XK_KP_0 and ksym <= x11.XK_KP_9) {
                    ksym = (ksym - x11.XK_KP_0) + x11.XK_0;
                }
            }
            if (x11.IsFunctionKey(ksym) or x11.IsKeypadKey(ksym) or x11.IsMiscFunctionKey(ksym) or x11.IsPFKey(ksym) or x11.IsPrivateKeypadKey(ksym))
                continue;

            switch (ksym) {
                x11.XK_Return => {
                    passwd[@intCast(len)] = 0;
                    var inputhash = c.crypt(&passwd, hash);
                    if (inputhash == null) {
                        std.log.err("binhlock: crypt: {s}\n", .{@tagName(std.os.errno(-1))});
                    } else {
                        running = c.strcmp(inputhash, hash) != 0;
                    }
                    if (running) {
                        _ = x11.XBell(dpy, 100);
                        failure = 1;
                    }
                    c.explicit_bzero(&passwd, @sizeOf(@TypeOf(passwd)));
                    len = 0;
                },
                x11.XK_Escape => {
                    c.explicit_bzero(&passwd, @sizeOf(@TypeOf(passwd)));
                    len = 0;
                },
                x11.XK_BackSpace => {
                    if (len > 0) {
                        len -= 1;
                        passwd[@intCast(len)] = 0;
                    }
                },
                else => {
                    if (num != 0 and !std.ascii.isControl(buf[0]) and (len + num < @sizeOf(@TypeOf(passwd)))) {
                        _ = c.memcpy(&passwd[@intCast(len)], &buf, @intCast(num));
                        len += num;
                    }
                },
            }

            const color: Color =
                if (len != 0) Color.Input else if (failure != 0 or config.failonclear != 0) Color.Failed else Color.Init;
            if (running and oldc != color) {
                for (0..@intCast(nscreens)) |screen| {
                    _ = x11.XSetWindowBackground(dpy, locks[screen].win, locks[screen].colors[@intFromEnum(color)]);
                    _ = x11.XClearWindow(dpy, locks[screen].win);
                }
                oldc = color;
            }
        } else if (rr.*.active != 0 and ev.type == rr.*.evbase + x11.RRScreenChangeNotify) {
            rre = @ptrCast(&ev);
            for (0..@intCast(nscreens)) |screen| {
                if (locks[screen].win == rre.*.window) {
                    if (rre.*.rotation == x11.RR_Rotate_90 or
                        rre.*.rotation == x11.RR_Rotate_270)
                    {
                        _ = x11.XResizeWindow(dpy, locks[screen].win, @intCast(rre.*.height), @intCast(rre.*.width));
                    } else {
                        _ = x11.XResizeWindow(dpy, locks[screen].win, @intCast(rre.*.width), @intCast(rre.*.height));
                    }
                    _ = x11.XClearWindow(dpy, locks[screen].win);
                    break;
                }
            }
        } else {
            for (0..@intCast(nscreens)) |screen| {
                _ = x11.XRaiseWindow(dpy, locks[screen].win);
            }
        }
    }
}

fn lockscreen(dpy: ?*x11.Display, rr: *Xrandr, screen: usize) ?Lock {
    if (dpy == null)
        return null;

    var lock: Lock = undefined;

    lock.screen = @intCast(screen);
    lock.root = x11.RootWindow(dpy, lock.screen);

    var color: x11.XColor = undefined;
    var dummy: x11.XColor = undefined;
    for (0..config.NumCols) |i| {
        _ = x11.XAllocNamedColor(dpy, x11.DefaultColormap(dpy, lock.screen), config.colorname[i], &color, &dummy);
        lock.colors[i] = color.pixel;
    }

    // init
    var wa: x11.XSetWindowAttributes = undefined;
    wa.override_redirect = 1;
    wa.background_pixel = lock.colors[@intFromEnum(Color.Init)];

    lock.win = x11.XCreateWindow(dpy, lock.root, 0, 0, @intCast(x11.DisplayWidth(dpy, lock.screen)), @intCast(x11.DisplayHeight(dpy, lock.screen)), 0, x11.DefaultDepth(dpy, lock.screen), x11.CopyFromParent, x11.DefaultVisual(dpy, lock.screen), x11.CWOverrideRedirect | x11.CWBackPixel, &wa);
    const curs = [_:0]u8{0} ** 8;
    lock.pmap = x11.XCreateBitmapFromData(dpy, lock.win, &curs, 8, 8);
    const invisible = x11.XCreatePixmapCursor(dpy, lock.pmap, lock.pmap, &color, &color, 0, 0);

    _ = x11.XDefineCursor(dpy, lock.win, invisible);

    var ptgrab: c_int = -1;
    var kbgrab: c_int = -1;
    // Try to grab mouse pointer *and* keyboard for 600ms, else fail the lock
    for (0..6) |i| {
        _ = i;
        if (ptgrab != x11.GrabSuccess) {
            ptgrab = x11.XGrabPointer(dpy, lock.root, x11.False, x11.ButtonPressMask | x11.ButtonReleaseMask | x11.PointerMotionMask, x11.GrabModeAsync, x11.GrabModeAsync, x11.None, invisible, x11.CurrentTime);
        }
        if (kbgrab != x11.GrabSuccess) {
            kbgrab = x11.XGrabKeyboard(dpy, lock.root, x11.True, x11.GrabModeAsync, x11.GrabModeAsync, x11.CurrentTime);
        }
        // input is grabbed: we can lock the screen
        if (ptgrab == x11.GrabSuccess and kbgrab == x11.GrabSuccess) {
            _ = x11.XMapRaised(dpy, lock.win);
            if (rr.*.active != 0)
                x11.XRRSelectInput(dpy, lock.win, x11.RRScreenChangeNotifyMask);

            _ = x11.XSelectInput(dpy, lock.root, x11.SubstructureNotifyMask);
            return lock;
        }
        // retry on AlreadyGrabbed but fail on other errors
        if ((ptgrab != x11.AlreadyGrabbed and ptgrab != x11.GrabSuccess) or
            (kbgrab != x11.AlreadyGrabbed and kbgrab != x11.GrabSuccess))
            break;

        std.time.sleep(100_000_000);
    }

    // we couldn't grab all input: fail out
    if (ptgrab != x11.GrabSuccess)
        std.log.err("binhlock: unable to grab mouse pointer for screen {d}\n", .{screen});
    if (kbgrab != x11.GrabSuccess)
        std.log.err("binhlock: unable to grab keyboard for screen {d}\n", .{screen});

    return null;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1 and args[1][0] == '-') {
        if (args[1].len == 2) {
            switch (args[1][1]) {
                'v' => version(),
                'h' => usage(0),
                else => {},
            }
        }
        usage(1);
    }

    const pwd_ptr = c.getpwnam(config.user);
    if (pwd_ptr == null) {
        const errno = std.os.errno(-1);
        const err_msg = if (errno != .SUCCESS) @tagName(errno) else "user entry not found";
        die("binhlock: getpwnam {s}: {s}\n", .{ config.user, err_msg });
    }

    const grp_ptr = c.getgrnam(config.group);
    if (grp_ptr == null) {
        const errno = std.os.errno(-1);
        const err_msg = if (errno != .SUCCESS) @tagName(errno) else "group entry not found";
        die("binhlock: getgrnam {s}: {s}\n", .{ config.group, err_msg });
    }

    const duid = pwd_ptr.*.pw_uid;
    const dgid = grp_ptr.*.gr_gid;

    try dontkillme(allocator);

    var hash = gethash();

    if (c.crypt("", hash) == null) {
        die("binhlock: crypt: {s}\n", .{@tagName(std.os.errno(-1))});
    }

    const dpy = x11.XOpenDisplay(null);
    if (dpy == null) {
        die("binhlock: cannot open display\n", .{});
    }

    // drop privileges
    if (c.setgroups(0, null) < 0)
        die("binhlock: setgroups: {s}\n", .{@tagName(std.os.errno(-1))});
    std.os.setgid(dgid) catch die("binhlock: setgid: {s}\n", .{@tagName(std.os.errno(-1))});
    std.os.setuid(duid) catch die("binhlock: setuid: {s}\n", .{@tagName(std.os.errno(-1))});

    // check for Xrandr support
    var rr: Xrandr = undefined;
    rr.active = x11.XRRQueryExtension(dpy, &rr.evbase, &rr.errbase);

    // get number of screens in display "dpy" and blank them
    const nscreens = x11.ScreenCount(dpy);
    var locks = try std.ArrayList(Lock).initCapacity(allocator, @intCast(nscreens));
    defer locks.deinit();

    for (0..@intCast(nscreens)) |i| {
        if (lockscreen(dpy, &rr, i)) |lock| {
            try locks.append(lock);
        } else {
            break;
        }
    }
    _ = x11.XSync(dpy, 0);

    // did we manage to lock everything?
    if (locks.items.len != nscreens)
        std.os.exit(1);

    // run post-lock command
    if (args.len > 1) {
        if (std.os.fork()) |fork_pid| {
            switch (fork_pid) {
                0 => {
                    if (std.c.close(x11.ConnectionNumber(dpy)) < 0)
                        die("binhlock: close: {s}\n", .{@tagName(std.os.errno(-1))});

                    std.process.execv(allocator, args[1..]) catch {
                        std.log.err("binhlock: execv {s}: {s}\n", .{ args[0], @tagName(std.os.errno(-1)) });
                        std.os.exit(1);
                    };
                },
                else => {},
            }
        } else |_| {
            die("binhlock: fork failed: {s}\n", .{@tagName(std.os.errno(-1))});
        }
    }

    // everything is now blank. Wait for the correct password
    readpw(dpy, &rr, locks.items, nscreens, hash);
}
