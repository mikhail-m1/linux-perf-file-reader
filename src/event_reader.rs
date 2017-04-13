use ::*;
use tools::{read_raw, read_string};
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
        } else  { None }
    }
}

fn sample_id_size(s: &sample_format::SampleFormat) -> usize {
    let mut size = 0;
    if s.contains(sample_format::TID) {
        size += 8;
    }
    if s.contains(sample_format::TIME) {
        size += 8;
    }
    if s.contains(sample_format::ID) {
        size += 8;
    }
    if s.contains(sample_format::STREAM_ID) {
        size += 8;
    }
    if s.contains(sample_format::CPU) {
        size += 8;
    }
    if s.contains(sample_format::IDENTIFIER) {
        size += 8;
    }
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
    Ok(ctr!(SampleId{pid, tid, time, id, stream_id, cpu, res, identifier}))
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
    let call_chain = vec![];// TODO support stacks
    use Event::Sample;
    Ok(ctr!(Sample{identifier, ip, pid, tid, time, addr, id, stream_id, cpu, res, period, call_chain}))
}

pub fn read_events(file: &mut File,
                   header: &PerfHeader,
                   attrs: &[EventAttributes])
                   -> Result<(Vec<Event>, u64, u64)> {
    let sample_format = attrs[0].sample_format;
    if !attrs
            .iter()
            .map(|x| x.sample_format)
            .all(|x| x == sample_format) {
        error!("different sample formats");
        return Err(ErrorKind::DifferentSampleFormat.into());
    }

    let sample_size = sample_id_size(&sample_format);

    let mut events = Vec::new();
    let mut position = file.seek(io::SeekFrom::Start(header.data.offset))?;
    let mut size = 0;
    let mut start = std::u64::MAX;
    let mut end = 0;
    debug!("read events");
    while size < header.data.size {
        let event_header = read_raw::<EventHeader>(file)?;
        debug!("{:x} {:?}", position, event_header);

        match event_header.record_type {
            RecordType::MMap => {
                let part = read_raw::<MMapPart>(file)?;
                let filename = read_string(file,
                                           event_header.size as usize - mem::size_of::<MMapPart>() -
                                           mem::size_of::<EventHeader>() -
                                           sample_size)?;
                let s = read_sample_id(file, &sample_format)?;
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
                let sample = read_sample(file, &sample_format)?;
                if let Event::Sample { time: Some(time), .. } = sample {
                    start = std::cmp::min(start, time);
                    end = std::cmp::max(end, time);
                }
                events.push(sample);
            }
            RecordType::MMap2 => {
                let part = read_raw::<MMap2Part>(file)?;
                let filename = read_string(file,
                                           event_header.size as usize -
                                           mem::size_of::<MMap2Part>() -
                                           mem::size_of::<EventHeader>() -
                                           sample_size)?;
                let s = read_sample_id(file, &sample_format)?;
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
                let part = read_raw::<ExitPart>(file)?;
                let s = read_sample_id(file, &sample_format)?;
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
                let part = read_raw::<CommPart>(file)?;
                let comm = read_string(file,
                                       event_header.size as usize - mem::size_of::<CommPart>() -
                                       mem::size_of::<EventHeader>() -
                                       sample_size)?;
                let s = read_sample_id(file, &sample_format)?;
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
