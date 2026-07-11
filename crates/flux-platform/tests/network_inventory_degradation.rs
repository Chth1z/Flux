use flux_platform::{NetworkInventoryDegradation, PlatformError};

#[test]
fn network_inventory_degradation_describes_initialization_descriptor_and_runtime_failures() {
    assert_eq!(
        NetworkInventoryDegradation::Initialization(PlatformError::UnsupportedPlatform("test"))
            .to_string(),
        "initialize network inventory observation: unsupported host platform 'test'"
    );
    assert_eq!(
        NetworkInventoryDegradation::DescriptorFailure { events: 0x18 }.to_string(),
        "network inventory descriptor reported epoll events 0x18"
    );
    assert_eq!(
        NetworkInventoryDegradation::Runtime(PlatformError::UnsupportedPlatform("test"))
            .to_string(),
        "drive network inventory observation: unsupported host platform 'test'"
    );
}
