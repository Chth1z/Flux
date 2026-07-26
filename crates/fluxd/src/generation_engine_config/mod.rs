mod address_reconciliation;
mod assembler;
mod bridge_environment;
mod candidate;
mod compiler;
mod desired_state;
mod engine_profile;
mod generation_record;
mod preparation;

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
pub(crate) use bridge_environment::*;
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
#[allow(
    unused_imports,
    reason = "the Generation facade is intentionally disconnected until planning authority exists"
)]
pub(crate) use engine_profile::*;
#[allow(
    unused_imports,
    reason = "prepared Generation persistence is connected through the A2 inspection seam"
)]
pub(crate) use generation_record::*;
#[allow(
    unused_imports,
    reason = "the canonical publisher is consumed only by bridge preparation during cutover"
)]
pub(crate) use preparation::*;

#[cfg(test)]
use engine_profile::parse_sing_box_version_output;

#[cfg(test)]
mod tests;
