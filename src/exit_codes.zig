pub const success: u8 = 0;
pub const usage: u8 = 64;
pub const dependency: u8 = 69;
pub const agent: u8 = 70;
pub const audit: u8 = 74;
pub const transient: u8 = 75;
pub const protocol: u8 = 76;
pub const authentication: u8 = 77;
pub const policy: u8 = 78;

pub const Class = enum {
    success,
    usage,
    dependency,
    agent,
    audit,
    transient,
    protocol,
    authentication,
    policy,

    pub fn code(self: Class) u8 {
        return switch (self) {
            .success => success,
            .usage => usage,
            .dependency => dependency,
            .agent => agent,
            .audit => audit,
            .transient => transient,
            .protocol => protocol,
            .authentication => authentication,
            .policy => policy,
        };
    }
};
