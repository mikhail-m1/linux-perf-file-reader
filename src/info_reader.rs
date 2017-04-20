use ::*;
use header::*;
use tools::{collect_n, read_raw, read_string};

pub fn read_info(file: &mut File, header: &PerfHeader) -> io::Result<(Info)> {
    let mut reader = HeaderInfoReader::new(file, header)?;

    reader.skip(header_flags::TRACING_DATA);
    reader.skip(header_flags::BUILD_ID);
    let hostname = reader.get_string(header_flags::HOSTNAME)?;
    let os_release = reader.get_string(header_flags::OSRELEASE)?;
    let tools_version = reader.get_string(header_flags::VERSION)?;
    let arch = reader.get_string(header_flags::ARCH)?;
    let cpu_count = reader.get::<CpuCount>(header_flags::NRCPUS)?;
    let cpu_description = reader.get_string(header_flags::CPUDESC)?;
    let cpu_id = reader.get_string(header_flags::CPUID)?;
    let total_memory = reader.get::<u64>(header_flags::TOTAL_MEM)?;
    let command_line = reader.get_string_array(header_flags::CMDLINE)?;
    let event_descriptions = reader.get_event_description()?;
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

    Ok(ctr!(Info{
        hostname,
        os_release,
        tools_version,
        cpu_count,
        event_descriptions,
        arch,
        cpu_id,
        cpu_description,
        total_memory,
        command_line,
        cpu_topology }
    ))
}

struct HeaderInfoReader<'a> {
    file: &'a mut File,
    sections: Vec<PerfFileSection>,
    current: usize,
    flags: HeaderFlags,
}

fn bits_count(mut v: u64) -> u8 {
    let mut c = 0;
    while v != 0 {
        v &= v - 1;
        c += 1;
    }
    c
}

impl<'a> HeaderInfoReader<'a> {
    fn new(file: &'a mut File, header: &PerfHeader) -> io::Result<Self> {
        file.seek(io::SeekFrom::Start(header.data.offset + header.data.size))?;
        let sections = collect_n(bits_count(header.flags.bits()) as usize,
                                 || read_raw::<PerfFileSection>(file))?;
        debug!("flags: {:x}, have {} info records, start at 0x{:x}",
               header.flags.bits(),
               sections.len(),
               header.data.offset + header.data.size);
        Ok(HeaderInfoReader {
               file: file,
               sections: sections,
               current: 0,
               flags: header.flags,
           })
    }

    fn seek(&mut self, flag: HeaderFlags) -> io::Result<()> {
        let section = &self.sections[self.current];
        debug!("Read section {} {:?}, size {}",
               self.current,
               flag,
               section.size);
        self.file.seek(io::SeekFrom::Start(section.offset))?;
        self.current += 1;
        Ok(())
    }

    fn get_string(&mut self, flag: HeaderFlags) -> io::Result<Option<String>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.seek(flag)?;
            let size = read_raw::<u32>(self.file)?;
            Ok(Some(read_string(self.file, size as usize)?))
        } else {
            Ok(None)
        }
    }

    fn get_string_array(&mut self, flag: HeaderFlags) -> io::Result<Option<Vec<String>>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.seek(flag)?;
            let count = read_raw::<u32>(self.file)? as usize;
            Ok(Some(collect_n(count, || {
                let size = read_raw::<u32>(self.file)? as usize;
                read_string(self.file, size)
            })?))
        } else {
            Ok(None)
        }
    }

    fn get_event_description(&mut self) -> io::Result<Option<Vec<EventDescription>>> {
        if self.flags.contains(header_flags::EVENT_DESC) && self.sections.len() > self.current {
            self.seek(header_flags::EVENT_DESC)?;
            let count = read_raw::<u32>(self.file)? as usize;
            let size = read_raw::<u32>(self.file)? as i64;
            debug!(" EVENT_DESC: count {}, size {}", count, size);
            let all_attributes = collect_n(count, || {
                let attributes = read_raw::<EventAttributes>(self.file)?;
                self.file
                    .seek(io::SeekFrom::Current(size - mem::size_of::<EventAttributes>() as i64))?;
                let id_count = read_raw::<u32>(self.file)? as usize;
                let name_size = read_raw::<u32>(self.file)?;
                let name = read_string(self.file, name_size as usize)?;
                let ids = collect_n(id_count, || read_raw::<u64>(self.file));
                ids.map(|ids| { ctr!(EventDescription{attributes, name, ids,}) })
            })?;
            Ok(Some(all_attributes))
        } else {
            Ok(None)
        }
    }

    fn get<T>(&mut self, flag: HeaderFlags) -> io::Result<Option<T>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.seek(flag)?;
            let v = read_raw::<T>(self.file)?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    fn skip(&mut self, flag: HeaderFlags) {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            debug!("Skip section {} {:?} size {}",
                   self.current,
                   flag,
                   self.sections[self.current].size);
            self.current += 1;
        }
    }

    fn has_more(&self) -> bool {
        self.sections.len() > self.current
    }
}
