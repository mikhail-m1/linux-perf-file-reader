use crate::tools::{collect_n, read_raw, read_string};
use crate::*;
use std::collections::HashMap;
use std::io::{Read, Seek};

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
enum RecordType {
    MMap = 1,
    Lost = 2,
    Comm = 3,
    Exit = 4,
    Fork = 7,
    Read = 8,
    Sample = 9,
    MMap2 = 10,
    Aux = 11,
    ItraceStart = 12,
    LostSamples = 13,
    Switch = 14,
    SwitchCpuWide = 15,
    Attr = 64,
    EventType = 65, /* depreceated */
    TracingData = 66,
    BuildId = 67,
    FinishedRound = 68,
    IdIndex = 69,
    AuxTraceInfo = 70,
    AuxTrace = 71,
    AuxTraceError = 72,
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
    flags: u32,
}

#[repr(C)]
#[derive(Debug)]
struct ExitPart {
    pid: u32,
    ppid: u32,
    tid: u32,
    ptid: u32,
    time: u64,
}

#[repr(C)]
#[derive(Debug)]
struct CommPart {
    pid: u32,
    tid: u32,
}

macro_rules! bool_to_option {
    ($v: expr, $c: expr) => {
        if $v {
            Some($c)
        } else {
            None
        }
    };
}

struct SampleReader {
    id_to_sample_format: HashMap<u64, SampleFormat>,
    sample_id_format: SampleFormat,
    sample_id_size: usize,
}

impl SampleReader {
    fn new(event_desciptions: &[EventDescription]) -> Result<Self> {
        if event_desciptions.len() == 0 {
            Err(ErrorKind::NoEventInInfoSection.into())
        } else if event_desciptions.len() > 1
            && !event_desciptions.iter().all(|d| {
                d.attributes
                    .sample_format
                    .contains(SampleFormat::IDENTIFIER)
            })
            && !event_desciptions.iter().all(|d| {
                d.attributes.sample_format == event_desciptions[0].attributes.sample_format
            })
        {
            Err(ErrorKind::NoIndentifierInEventInInfoAttributes.into())
        } else {
            let first = event_desciptions[0].attributes.sample_format;
            let map = event_desciptions
                .iter()
                .flat_map(|d| {
                    d.ids
                        .iter()
                        .map(move |id| (*id, d.attributes.sample_format))
                })
                .collect();
            Ok(SampleReader {
                id_to_sample_format: map,
                sample_id_format: first,
                sample_id_size: Self::sample_id_size(&first),
            })
        }
    }

    fn sample_id_size(s: &SampleFormat) -> usize {
        let mut size = 0;
        if s.contains(SampleFormat::TID) {
            size += 8;
        }
        if s.contains(SampleFormat::TIME) {
            size += 8;
        }
        if s.contains(SampleFormat::ID) {
            size += 8;
        }
        if s.contains(SampleFormat::STREAM_ID) {
            size += 8;
        }
        if s.contains(SampleFormat::CPU) {
            size += 8;
        }
        if s.contains(SampleFormat::IDENTIFIER) {
            size += 8;
        }
        size
    }

    fn read_sample_id(&self, file: &mut impl Read) -> io::Result<SampleId> {
        let s = self.sample_id_format;
        let pid = bool_to_option!(s.contains(SampleFormat::TID), read_raw(file)?);
        let tid = bool_to_option!(s.contains(SampleFormat::TID), read_raw(file)?);
        let time = bool_to_option!(s.contains(SampleFormat::TIME), read_raw(file)?);
        let id = bool_to_option!(s.contains(SampleFormat::ID), read_raw(file)?);
        let stream_id = bool_to_option!(s.contains(SampleFormat::STREAM_ID), read_raw(file)?);
        let cpu = bool_to_option!(s.contains(SampleFormat::CPU), read_raw(file)?);
        let res = bool_to_option!(s.contains(SampleFormat::CPU), read_raw(file)?);
        let identifier = bool_to_option!(s.contains(SampleFormat::IDENTIFIER), read_raw(file)?);
        Ok(SampleId {
            pid,
            tid,
            time,
            id,
            stream_id,
            cpu,
            res,
            identifier,
        })
    }

    fn read_sample(&self, file: &mut impl Read) -> io::Result<Event> {
        let mut s = self.sample_id_format;
        let identifier = bool_to_option!(s.contains(SampleFormat::IDENTIFIER), read_raw(file)?);
        if let Some(id) = identifier.as_ref() {
            if let Some(actual_format) = self.id_to_sample_format.get(id) {
                s = *actual_format;
            }
        }
        let ip = bool_to_option!(s.contains(SampleFormat::IP), read_raw(file)?);
        let pid = bool_to_option!(s.contains(SampleFormat::TID), read_raw(file)?);
        let tid = bool_to_option!(s.contains(SampleFormat::TID), read_raw(file)?);
        let time = bool_to_option!(s.contains(SampleFormat::TIME), read_raw(file)?);
        let addr = bool_to_option!(s.contains(SampleFormat::ADDR), read_raw(file)?);
        let id = bool_to_option!(s.contains(SampleFormat::ID), read_raw(file)?);
        let stream_id = bool_to_option!(s.contains(SampleFormat::STREAM_ID), read_raw(file)?);
        let cpu = bool_to_option!(s.contains(SampleFormat::CPU), read_raw(file)?);
        let res = bool_to_option!(s.contains(SampleFormat::CPU), read_raw(file)?);
        let period = bool_to_option!(s.contains(SampleFormat::PERIOD), read_raw(file)?);
        let call_chain: Vec<u64> = if !s.contains(SampleFormat::CALLCHAIN) {
            vec![]
        } else {
            collect_n(
                {
                    let x: u64 = read_raw(file)?;
                    x
                } as usize,
                || read_raw(file),
            )?
        };
        use Event::Sample;
        Ok(Sample {
            identifier,
            ip,
            pid,
            tid,
            time,
            addr,
            id,
            stream_id,
            cpu,
            res,
            period,
            call_chain,
        })
    }
}

pub fn read_events(
    file: &mut File,
    header: &PerfHeader,
    event_desciptions: &[EventDescription],
) -> Result<(Vec<Event>, u64, u64)> {
    let sample_reader = SampleReader::new(event_desciptions)?;

    let mut events = Vec::new();
    let mut position = file.seek(io::SeekFrom::Start(header.data.offset))?;
    let mut size = 0;
    let mut start = std::u64::MAX;
    let mut end = 0;
    debug!("read events");
    while size < header.data.size {
        let event_header: EventHeader = read_raw(file)?;
        debug!("{:x} {:?}", position, event_header);

        match event_header.record_type {
            RecordType::MMap => {
                let part: MMapPart = read_raw(file)?;
                let filename = read_string(
                    file,
                    event_header.size as usize
                        - mem::size_of::<MMapPart>()
                        - mem::size_of::<EventHeader>()
                        - sample_reader.sample_id_size,
                )?;
                let s = sample_reader.read_sample_id(file)?;
                events.push(Event::MMap {
                    pid: part.pid,
                    tid: part.tid,
                    addr: part.addr,
                    pgoff: part.pgoff,
                    len: part.len,
                    filename: filename,
                    sample_id: s,
                });
            }
            RecordType::Sample => {
                let sample = sample_reader.read_sample(file)?;
                if let Event::Sample {
                    time: Some(time), ..
                } = sample
                {
                    start = std::cmp::min(start, time);
                    end = std::cmp::max(end, time);
                }
                events.push(sample);
            }
            RecordType::MMap2 => {
                let part: MMap2Part = read_raw(file)?;
                let filename = read_string(
                    file,
                    event_header.size as usize
                        - mem::size_of::<MMap2Part>()
                        - mem::size_of::<EventHeader>()
                        - sample_reader.sample_id_size,
                )?;
                let s = sample_reader.read_sample_id(file)?;
                events.push(Event::MMap2 {
                    pid: part.pid,
                    tid: part.tid,
                    addr: part.addr,
                    pgoff: part.pgoff,
                    len: part.len,
                    maj: part.maj,
                    min: part.min,
                    ino: part.ino,
                    ino_generation: part.ino_generation,
                    prot: part.prot,
                    flags: part.flags,
                    filename: filename,
                    sample_id: s,
                });
            }
            RecordType::Exit => {
                let part: ExitPart = read_raw(file)?;
                let s = sample_reader.read_sample_id(file)?;
                events.push(Event::Exit {
                    pid: part.pid,
                    ppid: part.ppid,
                    tid: part.tid,
                    ptid: part.ptid,
                    time: part.time,
                    sample_id: s,
                });
                start = std::cmp::min(start, part.time);
                end = std::cmp::max(end, part.time);
            }
            RecordType::Comm => {
                let part: CommPart = read_raw(file)?;
                let comm = read_string(
                    file,
                    event_header.size as usize
                        - mem::size_of::<CommPart>()
                        - mem::size_of::<EventHeader>()
                        - sample_reader.sample_id_size,
                )?;
                let s = sample_reader.read_sample_id(file)?;
                events.push(Event::Comm {
                    pid: part.pid,
                    tid: part.tid,
                    comm: comm,
                    sample_id: s,
                });
            }
            RecordType::FinishedRound => events.push(Event::FinishedRound),
            _ => events.push(Event::Unsupported),
        }
        size += event_header.size as u64;
        position = file.seek(io::SeekFrom::Start(header.data.offset + size))?;
    }
    Ok((events, start, end))
}
