pub mod header_flags {
    bitflags!{
        pub flags HeaderFlags: u64 {
            const TRACING_DATA = 1 << 1,
            const BUILD_ID = 1 << 2,
            const HOSTNAME = 1 << 3,
            const OSRELEASE = 1 << 4,
            const VERSION = 1 << 5,
            const ARCH = 1 << 6,
            const NRCPUS = 1 << 7,
            const CPUDESC = 1 << 8,
            const CPUID = 1 << 9,
            const TOTAL_MEM = 1 << 10,
            const CMDLINE = 1 << 11,
            const EVENT_DESC = 1 << 12,
            const CPU_TOPOLOGY = 1 << 13,
            const NUMA_TOPOLOGY = 1 << 14,
            const BRANCH_STACK = 1 << 15,
            const PMU_MAPPINGS = 1 << 16,
            const GROUP_DESC = 1 << 17,
            const AUXTRACE = 1 << 18,
            const STAT = 1 << 19,
            const CACHE = 1 << 20,
        }
    }
}

pub use self::header_flags::HeaderFlags;

pub const PERF_FILE_SIGNATURE: u64 = 0x32454c4946524550;

#[repr(C)]
#[derive(Debug)]
pub struct PerfHeader {
    pub magic: u64, /* PERFILE2 */
    pub size: u64, /* size of the header */
    pub attr_size: u64, /* size of an attribute in attrs */
    pub attrs: PerfFileSection,
    pub data: PerfFileSection,
    pub header_types: PerfFileSection,
    pub flags: HeaderFlags,
    pub flags1: [u64; 3],
}

#[repr(C)]
#[derive(Debug)]
pub struct PerfFileSection {
    pub offset: u64, /* offset from start of file */
    pub size: u64, /* size of the section */
}
