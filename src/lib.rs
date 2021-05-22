///
pub mod packet;

// FIXME(async): Implement async read/write traits for types
// FIXME(craft): Chew on header types
// FIXME(craft): Make Flag bitfields optional on all packets
// FIXME(craft): Preserve order of var arg fields
// FIXME(perf): Consider making packet types zero-alloc
// FIXME(craft): audit expect/unwrap usage on user-provided input
// FIXME(craft): move common code out of individual packet modules
// FIXME(craft): rename packet protocol
