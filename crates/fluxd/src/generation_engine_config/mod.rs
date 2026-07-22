mod candidate;
mod compiler;
mod engine_profile;

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
    reason = "the Generation facade is intentionally disconnected until planning authority exists"
)]
pub(crate) use engine_profile::*;

#[cfg(test)]
use engine_profile::parse_sing_box_version_output;

#[cfg(test)]
mod tests;
