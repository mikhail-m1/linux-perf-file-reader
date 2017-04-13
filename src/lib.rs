#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate serde_derive;
extern crate serde;

use std::fs::File;
use std::io::Seek;
use std::{mem, io};

macro_rules! ctr {
    ($name:tt{$($field: tt),*}) => {$name{$($field: $field,)* }};
    ($name:tt{$($field: tt),*,}) => {$name{$($field: $field,)* }};
}

mod info_reader;
mod event_reader;
mod header;
use header::*;
mod tools;
use tools::read_raw;

mod errors {
    error_chain! {
        foreign_links {
            IOError(::std::io::Error);
        }

        errors {
            InvalidSinature {
                description("invalid perf file signature")
                display("invalid perf file signature")
            }
            DifferentSampleFormat {
                description("different sample format")
                display("different sample format")
            }
        }
    }
}

use errors::*;

pub use errors::Error;
pub use errors::ErrorKind;

#[repr(u32)]
#[derive(Debug)]
pub enum PerfType {
    Hardware = 0,
    Software = 1,
    Tracepoint = 2,
    HwCache = 3,
    Raw = 4,
    Breakpoint = 5,
}

#[repr(u64)]
#[derive(Debug)]
pub enum HwId {
    CpuCycles = 0,
    Instructions = 1,
    CacheReferences = 2,
    CacheMisses = 3,
    BranchInstructions = 4,
    BranchMisses = 5,
    BusCycles = 6,
    StalledCyclesFrontend = 7,
    StalledCyclesBackend = 8,
    RefCpuCycles = 9,
}

pub mod attr_flags {
    bitflags! {
        pub flags AttrFlags: u64 {
            const DISABLED          = 1, /* off by default        */
            const INHERIT           = 1 << 1, /* children inherit it   */
            const PINNED            = 1 << 2, /* must always be on PMU */
            const EXLUSIVE          = 1 << 3, /* only group on PMU     */
            const EXCLUDE_USER      = 1 << 4, /* don't count user      */
            const EXCLUDE_KERNEL    = 1 << 5, /* ditto kernel          */
            const EXCLUDE_HV        = 1 << 6, /* ditto hypervisor      */
            const EXCLUDE_IDLE      = 1 << 7, /* don't count when idle */
            const MMAP              = 1 << 8, /* include mmap data     */
            const COMM              = 1 << 9, /* include comm data     */
            const FREQ              = 1 << 10, /* use freq, not period  */
            const INHERIT_STAT      = 1 << 11, /* per task counts       */
            const ENABLE_ON_EXEC    = 1 << 12, /* next exec enables     */
            const TASK              = 1 << 13, /* trace fork/exit       */
            const WATERMARK         = 1 << 14, /* wakeup_watermark      */
            /*
             * precise_ip:
             *
             *  0 - SAMPLE_IP can have arbitrary skid
             *  1 - SAMPLE_IP must have constant skid
             *  2 - SAMPLE_IP requested to have 0 skid
             *  3 - SAMPLE_IP must have 0 skid
             */
            const PRECISE_IP1      = 1 << 15,
            const PRECISE_IP2      = 1 << 16,
            const MMAP_DATA         = 1 << 17, /* non-exec mmap data    */
            const SAMPLE_ID_ALL     = 1 << 18, /* sample_type all events */
            const EXCLUDE_HOST      = 1 << 19, /* don't count in host   */
            const EXCLUDE_GUEST     = 1 << 20, /* don't count in guest  */
            const EXCLUDE_CALLCHAIN_KERNEL  = 1 << 21, /* exclude kernel callchains */
            const EXCLUDE_CALLCHAIN_USER  = 1 << 22, /* exclude user callchains */
            const MMAP2             = 1 << 23, /* include mmap with inode data     */
            const COMM_EXEC         = 1 << 24, /* flag comm events that are due to an exec */
            const USE_CLOCKID       = 1 << 25, /* use @clockid for time fields */
            const CONTEXT_SWITCH    = 1 << 26, /* context switch data */
            const WRITE_BACKWARD    = 1 << 27  /* Write ring buffer from end to beginning */
        }
    }
}

pub mod sample_format {
    bitflags!{
        pub flags SampleFormat: u64 {
            const IP	    	= 1 << 0,
            const TID			= 1 << 1,
            const TIME			= 1 << 2,
            const ADDR			= 1 << 3,
            const READ			= 1 << 4,
            const CALLCHAIN	    = 1 << 5,
            const ID			= 1 << 6,
            const CPU			= 1 << 7,
            const PERIOD		= 1 << 8,
            const STREAM_ID		= 1 << 9,
            const RAW			= 1 << 10,
            const BRANCH_STACK	= 1 << 11,
            const REGS_USER		= 1 << 12,
            const STACK_USER	= 1 << 13,
            const WEIGHT		= 1 << 14,
            const DATA_SRC		= 1 << 15,
            const IDENTIFIER	= 1 << 16,
            const TRANSACTION	= 1 << 17,
            const REGS_INTR		= 1 << 18,
        }
    }
}

pub mod read_format {
    bitflags!{
        pub flags ReadFormat: u64 {
            const TOTAL_TIME_ENABLED    = 1 << 0,
            const TOTAL_TIME_RUNNING	= 1 << 1,
            const ID				    = 1 << 2,
            const GROUP			        = 1 << 3,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct EventAttributes {
    pub perf_type: PerfType,
    pub size: u32,
    pub config: u64, //TODO: HwId for type hardware,
    pub sample_period_or_freq: u64,
    pub sample_format: sample_format::SampleFormat,
    pub read_format: read_format::ReadFormat,
    pub flags: attr_flags::AttrFlags,
    pub wakeup_events_or_watermakr: u32, /* wakeup every n events or bytes before wakeup   */
    pub bp_type: u32,
    pub bp_addr_or_config1: u32,
    pub bp_len_or_config2: u64,
    pub branch_sample_type: u64, // enum perf_branch_sample_type
    pub sample_regs_user: u64, // Defines set of user regs to dump on samples See asm/perf_regs.h.
    pub sample_stack_user: u32, // Defines size of the user stack to dump on samples.
    pub clockid: i32,
    /*
     * Defines set of regs to dump for each sample
     * state captured on:
     *  - precise = 0: PMU interrupt
     *  - precise > 0: sampled instruction
     */
    pub sample_regs_intr: u64,
    pub aux_watermark: u32, //Wakeup watermark for AUX area
    pub sample_max_stack: u16,
    pub reserved_2: u16,
}


#[derive(Debug)]
pub struct Perf {
    pub info: Info,
    pub event_attributes: Vec<EventAttributes>,
    pub events: Vec<Event>,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Serialize)]
pub struct Info {
    pub hostname: Option<String>,
    pub os_release: Option<String>,
    pub tools_version: Option<String>,
    pub arch: Option<String>,
    pub cpu_count: Option<CpuCount>,
    pub cpu_description: Option<String>,
    pub cpu_id: Option<String>,
    pub total_memory: Option<u64>,
    pub command_line: Option<Vec<String>>,
    pub cpu_topology: Option<Vec<String>>,
    pub event_description: Option<Vec<EventDescription>>,
    // TODO add others
}

#[repr(C)]
#[derive(Debug, Serialize)]
pub struct CpuCount {
    pub online: u32,
    pub available: u32,
}

#[derive(Debug, Serialize)]
pub struct EventDescription {
    #[serde(skip_serializing)]
    pub attributes: EventAttributes,
    pub name: String,
    pub ids: Vec<u64>,
}

#[derive(Debug)]
pub enum Event {
    MMap {
        pid: u32,
        tid: u32,
        addr: u64,
        len: u64,
        pgoff: u64,
        filename: String,
        sample_id: SampleId,
    },
    MMap2 {
        pid: u32,
        tid: u32,
        addr: u64,
        len: u64,
        pgoff: u64,
        maj: u32,
        min: u32,
        ino: u64,
        ino_generation: u64,
        prot: u32,
        flags: u32,
        filename: String,
        sample_id: SampleId,
    },
    Sample {
        identifier: Option<u64>,
        ip: Option<u64>,
        pid: Option<u32>,
        tid: Option<u32>,
        time: Option<u64>,
        addr: Option<u64>,
        id: Option<u64>,
        stream_id: Option<u64>,
        cpu: Option<u32>,
        res: Option<u32>,
        period: Option<u64>,
        //TODO read_format
        call_chain: Vec<u64>, // TODO add others
    },
    Exit {
        pid: u32,
        ppid: u32,
        tid: u32,
        ptid: u32,
        time: u64,
        sample_id: SampleId,
    },
    Comm {
        pid: u32,
        tid: u32,
        comm: String,
        sample_id: SampleId,
    },
    FinishedRound,
    Unsupported,
}

#[repr(C)]
#[derive(Debug)]
pub struct SampleId {
    pub pid: Option<u32>,
    pub tid: Option<u32>,
    pub time: Option<u64>,
    pub id: Option<u64>,
    pub stream_id: Option<u64>,
    pub cpu: Option<u32>,
    pub res: Option<u32>,
    pub identifier: Option<u64>,
}

pub fn is_perf_file<P: std::convert::AsRef<std::path::Path>>(path: &P) -> Result<(bool)> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() < mem::size_of::<PerfHeader>() as u64 {
        return Ok(false);
    }
    let mut file = File::open(&path)?;
    let header = read_raw::<PerfHeader>(&mut file)?;
    Ok(header.magic == PERF_FILE_SIGNATURE)
}

pub fn read_perf_file_info<P: std::convert::AsRef<std::path::Path>>(path: &P) -> Result<(Info)> {
    let mut file = File::open(path)?;
    let header = read_raw::<PerfHeader>(&mut file)?;
    if header.magic != PERF_FILE_SIGNATURE {
        return Err(ErrorKind::InvalidSinature.into());
    }
    Ok(info_reader::read_info(&mut file, &header)?)
}

pub fn read_perf_file<P: std::convert::AsRef<std::path::Path>>(path: &P) -> Result<(Perf)> {
    let mut file = File::open(path)?;
    debug!("read header");
    let header = read_raw::<PerfHeader>(&mut file)?;
    if header.magic != PERF_FILE_SIGNATURE {
        return Err(ErrorKind::InvalidSinature.into());
    }
    debug!("header: {:?}\nread info", header);
    let info = info_reader::read_info(&mut file, &header)?;

    debug!("read attr");
    let event_attributes = (0..(header.attrs.size / header.attr_size))
        .map(|i| {
                 file.seek(io::SeekFrom::Start(header.attrs.offset + i * header.attr_size))?;
                 Ok(read_raw::<EventAttributes>(&mut file)?)
             })
        .collect::<Result<Vec<_>>>()?;

    let (events, start, end) = event_reader::read_events(&mut file, &header, &event_attributes)?;
    Ok(ctr!(Perf{info, event_attributes, events, start, end,}))
}
