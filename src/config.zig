pub const Color = enum {
    Init,
    Input,
    Failed,
    NumCols,
};
pub const NumCols = @intFromEnum(Color.NumCols);

// user and group to drop privileges to
pub const user = "nobody";
pub const group = "nobody";

pub const colorname = blk: {
    var colors: [NumCols][:0]const u8 = undefined;
    colors[@intFromEnum(Color.Init)] = "#282A36"; // after initialization
    colors[@intFromEnum(Color.Input)] = "#BD93F9"; // during input
    colors[@intFromEnum(Color.Failed)] = "#FF5555"; // wrong password
    break :blk colors;
};

// treat a cleared input like a wrong password (color)
pub const failonclear = 1;
