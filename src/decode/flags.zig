//! Problems a transfer decoder met. Decoding always continues; these say what was tolerated.
pub const Flags = packed struct(u8) {
    /// Bytes that are not valid in the encoding were skipped (base64) or kept literally
    /// (quoted-printable).
    invalid_input: bool = false,
    /// base64 padding was followed by more data, which was decoded too.
    padding_inside: bool = false,
    /// The body ended inside a base64 quantum.
    truncated: bool = false,
    _: u5 = 0,

    pub fn any(self: Flags) bool {
        return self.invalid_input or self.padding_inside or self.truncated;
    }

    pub fn merge(a: Flags, b: Flags) Flags {
        return .{
            .invalid_input = a.invalid_input or b.invalid_input,
            .padding_inside = a.padding_inside or b.padding_inside,
            .truncated = a.truncated or b.truncated,
        };
    }
};
