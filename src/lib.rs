#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;
#[macro_use] 
extern crate log;
#[macro_use] 
extern crate bitflags;

use std::fs::File;
use std::{mem, slice, io};
use std::io::{Read, Seek};

mod errors {
    error_chain! { 
        errors {
            IOError
        }
    }
}

use errors::*;

#[repr(C)]
#[derive(Debug)]
struct PerfFileSection {
	pub offset: u64,	/* offset from start of file */
	pub size: u64		/* size of the section */
}

mod header_flags {
    bitflags!{
        pub flags HeaderFlags: u64 {
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

use header_flags::HeaderFlags;

#[repr(C)]
#[derive(Debug)]
struct PerfHeader {
	pub magic : u64,		/* PERFILE2 */
	pub size: u64,		/* size of the header */
	pub attr_size: u64,	/* size of an attribute in attrs */
	pub attrs: PerfFileSection,
	pub data: PerfFileSection,
	pub header_types: PerfFileSection,
	pub flags: HeaderFlags,
	pub flags1: [u64;3],
}

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum PerfType {
    Hardware		= 0,
	Software		= 1,
	Tracepoint		= 2,
	HwCache			= 3,
	Raw				= 4,
	Breakpoint		= 5,
}

#[repr(u64)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum HwId {
    CpuCycles		        = 0,
	Instructions		    = 1,
    CacheReferences         = 2,
	CacheMisses	            = 3,
	BranchInstructions	    = 4,
	BranchMisses	        = 5,
	BusCycles		        = 6,
	StalledCyclesFrontend	= 7,
	StalledCyclesBackend	= 8,
	RefCpuCycles	    	= 9,
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
	pub perf_type: PerfType, //Major type: hardware/software/tracepoint/etc.
	pub size: u32,
	pub hw_id: HwId,
	pub sample_period_or_freq: u64,
	pub sample_format: sample_format::SampleFormat,
	pub read_format: /*u64, */read_format::ReadFormat,
	pub flags: attr_flags::AttrFlags,
	pub wakeup_events_or_watermakr: u32, /* wakeup every n events or bytes before wakeup   */
	pub bp_type: u32,
    pub bp_addr_or_config1: u32,
	pub bp_len_or_config2 :u64,
    pub branch_sample_type : u64, // enum perf_branch_sample_type 
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
	pub sample_max_stack : u16,
	pub reserved_2: u16
}

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
enum RecordType {
	MMap			= 1,
    Lost            = 2,
	Comm			= 3,
	Exit			= 4,
    Fork            = 7,
    Read            = 8,
	Sample			= 9,
    MMap2           = 10,
    Aux             = 11,
    ItraceStart     = 12,
    LostSamples     = 13,
    Switch          = 14,
    SwitchCpuWide   = 15,
	Attr			= 64,
	EventType		= 65, /* depreceated */
	TracingData	    = 66,
	BuildId		    = 67,
	FinishedRound	= 68,
	IdIndex			= 69,
	AuxTraceInfo	= 70,
	AuxTrace		= 71,
	AuxTraceError	= 72,
}

#[repr(C)]
#[derive(Debug)]
struct EventHeader {
	record_type: RecordType,
	misc: u16,
	size: u16,
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

#[repr(C)]
#[derive(Debug)]
struct MMapPart {
	pid: u32,
    tid: u32,
	addr: u64,
	len: u64,
	pgoff: u64,
}

#[repr(C)]
#[derive(Debug)]
struct MMap2Part {
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
    flags: u32
}

#[repr(C)]
#[derive(Debug)]
struct ExitPart {
	pid: u32,
    ppid: u32,
	tid: u32,
    ptid: u32,
    time: u64
}

#[repr(C)]
#[derive(Debug)]
struct CommPart {
	pid: u32,
    tid: u32,
}

#[derive(Debug)]
pub struct Info {
    pub hostname: Option<String>,
    pub os_release: Option<String>,
    pub tools_version: Option<String>,
    pub arch: Option<String>,
    pub cpu_description: Option<String>,
    pub cpu_id: Option<String>,
    pub total_memory: Option<u64>,
    pub command_line: Option<Vec<String>>,
    pub cpu_topology: Option<Vec<String>>,
    // TODO add others
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
        call_chain: Vec<u64>
        // TODO add others
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
    Unsupported
}

#[derive(Debug)]
pub struct Perf {
    pub info: Info,
    pub event_attributes: Vec<EventAttributes>,
    pub events: Vec<Event>,
}

fn read_raw<T>(file: &mut Read) -> io::Result<T> {
    let size = mem::size_of::<T>();
    unsafe {
        let mut t: T = mem::uninitialized();
        let mut slice = slice::from_raw_parts_mut(mem::transmute(&mut t), size);
        file.read_exact(slice)?;
        Ok(t)
    }
}

fn read_string(file: &mut Read, size: usize) -> io::Result<String> {
    let mut buff = vec![0u8; size];
    file.read_exact(&mut buff)?;
    let end = buff.iter().position(|x| *x == 0).unwrap_or(buff.len());
    let s = String::from_utf8_lossy(&buff[0..end]).to_string();
    //debug!("read str max size:{}, result: {}, `{}`", size, s.len(), s);
    Ok(s)
}

macro_rules! bool_to_option {
    ($v: expr, $c: expr) => {
        if $v {
            Some($c)
        } else  { None }
    }
}

fn sample_id_size(s: &sample_format::SampleFormat) -> usize {
    let mut size = 0;
    if s.contains(sample_format::TID) { size += 8; }
    if s.contains(sample_format::TIME) { size += 8; }
    if s.contains(sample_format::ID) { size += 8; }
    if s.contains(sample_format::STREAM_ID) { size += 8; }
    if s.contains(sample_format::CPU) { size += 8; }
    if s.contains(sample_format::IDENTIFIER) { size += 8; }
    size
}

fn read_sample_id(file: &mut Read, s: &sample_format::SampleFormat) -> io::Result<SampleId> {
    let pid = bool_to_option!(s.contains(sample_format::TID), read_raw(file)?);
    let tid = bool_to_option!(s.contains(sample_format::TID), read_raw(file)?);
    let time = bool_to_option!(s.contains(sample_format::TIME), read_raw(file)?);
    let id = bool_to_option!(s.contains(sample_format::ID), read_raw(file)?);
    let stream_id = bool_to_option!(s.contains(sample_format::STREAM_ID), read_raw(file)?);
    let cpu = bool_to_option!(s.contains(sample_format::CPU), read_raw(file)?);
    let res = bool_to_option!(s.contains(sample_format::CPU), read_raw(file)?);
    let identifier = bool_to_option!(s.contains(sample_format::IDENTIFIER), read_raw(file)?);
    Ok(SampleId { pid: pid, tid: tid, time:time, id: id, stream_id: stream_id, cpu: cpu, res: res, identifier: identifier})
}

fn read_sample(file: &mut Read, s: &sample_format::SampleFormat) -> io::Result<Event> {
    let identifier = bool_to_option!(s.contains(sample_format::IDENTIFIER), read_raw(file)?);
    let ip = bool_to_option!(s.contains(sample_format::IP), read_raw(file)?);
    let pid = bool_to_option!(s.contains(sample_format::TID), read_raw(file)?);
    let tid = bool_to_option!(s.contains(sample_format::TID), read_raw(file)?);
    let time = bool_to_option!(s.contains(sample_format::TIME), read_raw(file)?);
    let addr = bool_to_option!(s.contains(sample_format::ADDR), read_raw(file)?);
    let id = bool_to_option!(s.contains(sample_format::ID), read_raw(file)?);
    let stream_id = bool_to_option!(s.contains(sample_format::STREAM_ID), read_raw(file)?);
    let cpu = bool_to_option!(s.contains(sample_format::CPU), read_raw(file)?);
    let res = bool_to_option!(s.contains(sample_format::CPU), read_raw(file)?);
    let period = bool_to_option!(s.contains(sample_format::PERIOD), read_raw(file)?);
    //TODO support stacks*/
    Ok(Event::Sample { identifier: identifier, ip: ip, pid: pid, tid: tid,  time:time, addr: addr, id: id, stream_id: stream_id, cpu: cpu, res: res, period: period, call_chain: vec![]})
}

struct HeaderInfoReader<'a> {
    file: &'a mut File, 
    sections: Vec<PerfFileSection>, 
    current: usize, 
    flags: HeaderFlags
}

impl<'a> HeaderInfoReader<'a> {
    fn new(file: &'a mut File, header: &PerfHeader) -> io::Result<Self> {
        file.seek(io::SeekFrom::Start(header.data.offset + header.data.size))?;
        let mut sections = Vec::new();
        loop {
            let section = read_raw::<PerfFileSection>(file)?;
            if section.offset == 0 {
                break;
            }
            sections.push(section);

        }
        Ok(HeaderInfoReader{ file: file, sections: sections, current: 0, flags: header.flags })
    }

    fn get_string(&mut self, flag: HeaderFlags) -> io::Result<Option<String>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            let section = &self.sections[self.current];
            self.file.seek(io::SeekFrom::Start(section.offset))?;
            let size = read_raw::<u32>(self.file)?;
            self.current += 1;
            Ok(Some(read_string(self.file, size as usize)?))
        } else {
            Ok(None)
        }
    }

    fn get_string_array(&mut self, flag: HeaderFlags) -> io::Result<Option<Vec<String>>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            let section = &self.sections[self.current];
            self.file.seek(io::SeekFrom::Start(section.offset))?;
            let count = read_raw::<u32>(self.file)?;
            let mut array = Vec::new();
            for _ in 0..count {
                let size = read_raw::<u32>(self.file)?;
                array.push(read_string(self.file, size as usize)?);
            }
            self.current += 1;
            Ok(Some(array))
        } else {
            Ok(None)
        }
    }

    fn get<T>(&mut self, flag: HeaderFlags) -> io::Result<Option<T>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            let v = read_raw::<T>(self.file)?;
            self.current += 1;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    fn skip(&mut self, flag: HeaderFlags) {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.current += 1;
        }
    }

    fn has_more(&self) -> bool {
        self.sections.len() > self.current
    }
}

fn read_info(file: &mut File, header: &PerfHeader) -> io::Result<(Info)> {
    let mut reader = HeaderInfoReader::new(file, header)?;
    
    reader.skip(header_flags::BUILD_ID);
    let hostname = reader.get_string(header_flags::HOSTNAME)?;
    let os_release = reader.get_string(header_flags::OSRELEASE)?;
    let tools_version = reader.get_string(header_flags::VERSION)?;
    let arch = reader.get_string(header_flags::ARCH)?;
    reader.skip(header_flags::NRCPUS);
    let cpu_description = reader.get_string(header_flags::CPUDESC)?;
    let cpu_id = reader.get_string(header_flags::CPUID)?;
    let total_memory = reader.get::<u64>(header_flags::TOTAL_MEM)?;
    let command_line = reader.get_string_array(header_flags::CMDLINE)?;
    reader.skip(header_flags::EVENT_DESC);
    //TODO: check is all parsed?
    let cpu_topology = reader.get_string_array(header_flags::CPU_TOPOLOGY)?;
    reader.skip(header_flags::NUMA_TOPOLOGY);
    reader.skip(header_flags::BRANCH_STACK);
    reader.skip(header_flags::PMU_MAPPINGS);
    reader.skip(header_flags::GROUP_DESC);
    reader.skip(header_flags::AUXTRACE);
    reader.skip(header_flags::STAT);
    reader.skip(header_flags::CACHE);
    if reader.has_more() {
        warn!("Unknown flags in header");
    }

    return Ok((Info{hostname: hostname, os_release: os_release, tools_version: tools_version,
        arch: arch, cpu_id: cpu_id, cpu_description: cpu_description, total_memory: total_memory, command_line: command_line, cpu_topology: cpu_topology}));
}

pub fn read_perf_file<P: std::convert::AsRef<std::path::Path>>(path: P) -> Result<(Perf)> {
    let mut file = File::open(path).chain_err(|| ErrorKind::IOError)?;
    let header = read_raw::<PerfHeader>(&mut file).chain_err(|| ErrorKind::IOError)?;
    let info = read_info(&mut file, &header).chain_err(|| ErrorKind::IOError)?;
        
    let attrs = (0..(header.attrs.size / header.attr_size)).map(|i| {
        file.seek(io::SeekFrom::Start(header.attrs.offset + i * header.attr_size)).chain_err(|| ErrorKind::IOError)?;
        read_raw::<EventAttributes>(&mut file).chain_err(|| ErrorKind::IOError)
    }).collect::<Result<Vec<_>>>()?;
    
    let sample_format = attrs[0].sample_format;
    let sample_size = sample_id_size(&sample_format);
        
    let mut events = Vec::new();
    let mut position = file.seek(io::SeekFrom::Start(header.data.offset)).chain_err(|| ErrorKind::IOError)?;
    let mut size = 0;
    while size < header.data.size {
        let event_header = read_raw::<EventHeader>(&mut file).chain_err(|| ErrorKind::IOError)?;
        debug!("{:x} {:?}", position, event_header);

        match event_header.record_type {
            RecordType::MMap => {
                let part = read_raw::<MMapPart>(&mut file).chain_err(|| ErrorKind::IOError)?;
                let filename = read_string(&mut file, event_header.size as usize - 
                            mem::size_of::<MMapPart>() - 
                            mem::size_of::<EventHeader>() -
                            sample_size).chain_err(|| ErrorKind::IOError)?;
                let s = read_sample_id(&mut file, &sample_format).chain_err(|| ErrorKind::IOError)?;
                events.push(Event::MMap{pid: part.pid, tid: part.tid, addr:part.addr, pgoff: part.pgoff, len: part.len, filename: filename, sample_id: s});
            },
            RecordType::Sample => {
                events.push(read_sample(&mut file, &sample_format).chain_err(|| ErrorKind::IOError)?);
            },
            RecordType::MMap2 => {
                let part = read_raw::<MMap2Part>(&mut file).chain_err(|| ErrorKind::IOError)?;
                let filename = read_string(&mut file, event_header.size as usize - 
                            mem::size_of::<MMap2Part>() - 
                            mem::size_of::<EventHeader>() -
                            sample_size).chain_err(|| ErrorKind::IOError)?;
                let s = read_sample_id(&mut file, &sample_format).chain_err(|| ErrorKind::IOError)?;
                events.push(Event::MMap2{pid: part.pid, tid: part.tid, addr:part.addr, pgoff: part.pgoff, len: part.len, 
                    maj: part.maj, min: part.min, ino: part.ino, ino_generation: part.ino_generation, prot: part.prot, flags: part.flags, filename: filename, sample_id: s});
            },
            RecordType::Exit => {
                let part = read_raw::<ExitPart>(&mut file).chain_err(|| ErrorKind::IOError)?;
                let s = read_sample_id(&mut file, &sample_format).chain_err(|| ErrorKind::IOError)?;
                events.push(Event::Exit{pid: part.pid, ppid: part.ppid, tid: part.tid, ptid: part.ptid, time: part.time, sample_id: s});
            },
            RecordType::Comm => {
                let part = read_raw::<CommPart>(&mut file).chain_err(|| ErrorKind::IOError)?;
                let comm = read_string(&mut file, event_header.size as usize - 
                            mem::size_of::<CommPart>() - 
                            mem::size_of::<EventHeader>() -
                            sample_size).chain_err(|| ErrorKind::IOError)?;
                let s = read_sample_id(&mut file, &sample_format).chain_err(|| ErrorKind::IOError)?;
                events.push(Event::Comm{pid: part.pid, tid: part.tid, comm: comm, sample_id: s});
            },
            RecordType::FinishedRound => events.push(Event::FinishedRound),
            _ => events.push(Event::Unsupported),
        }
        size += event_header.size as u64;
        position = file.seek(io::SeekFrom::Start(header.data.offset + size)).chain_err(|| ErrorKind::IOError)?;
    }
    Ok(Perf{info: info, event_attributes: attrs, events: events})
}

