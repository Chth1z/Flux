mod address_reconciliation;
mod assembler;
mod candidate;
mod compiler;
mod desired_state;
mod engine_profile;
#[cfg(test)]
mod generation_record;

#[allow(
    unused_imports,
    reason = "A3 retains non-mutating address inputs for the later native Generation cutover"
)]
pub(crate) use address_reconciliation::*;
#[allow(
    unused_imports,
    reason = "the Generation assembler remains non-mutating until coordinator cutover"
)]
pub(crate) use assembler::*;
#[allow(
    unused_imports,
    reason = "the Generation facade is intentionally disconnected until planning authority exists"
)]
pub(crate) use candidate::*;
#[allow(
    unused_imports,
    reason = "the Generation facade is intentionally disconnected until planning authority exists"
)]
pub(crate) use compiler::*;
#[allow(
    unused_imports,
    reason = "the Desired State compiler is exercised before production writer cutover"
)]
pub(crate) use desired_state::*;
#[cfg(test)]
use engine_profile::parse_sing_box_version_output;
#[allow(
    unused_imports,
    reason = "the Generation facade is intentionally disconnected until planning authority exists"
)]
pub(crate) use engine_profile::*;
#[cfg(test)]
pub(crate) use generation_record::*;

#[cfg(test)]
mod tests;
