use crate::*;
use header::*;
use tools::{collect_n, read_raw, read_string};

pub fn read_info(file: &mut File, header: &PerfHeader) -> io::Result<Info> {
    let mut reader = HeaderInfoReader::new(file, header)?;

    reader.skip(HeaderFlags::TRACING_DATA);
    reader.skip(HeaderFlags::BUILD_ID);
    let hostname = reader.get_string(HeaderFlags::HOSTNAME)?;
    let os_release = reader.get_string(HeaderFlags::OSRELEASE)?;
    let tools_version = reader.get_string(HeaderFlags::VERSION)?;
    let arch = reader.get_string(HeaderFlags::ARCH)?;
    let cpu_count = reader.get::<CpuCount>(HeaderFlags::NRCPUS)?;
    let cpu_description = reader.get_string(HeaderFlags::CPUDESC)?;
    let cpu_id = reader.get_string(HeaderFlags::CPUID)?;
    let total_memory = reader.get::<u64>(HeaderFlags::TOTAL_MEM)?;
    let command_line = reader.get_string_array(HeaderFlags::CMDLINE)?;
    let event_descriptions = reader.get_event_description()?;
    let cpu_topology = reader.get_string_array(HeaderFlags::CPU_TOPOLOGY)?;
    reader.skip(HeaderFlags::NUMA_TOPOLOGY);
    reader.skip(HeaderFlags::BRANCH_STACK);
    reader.skip(HeaderFlags::PMU_MAPPINGS);
    reader.skip(HeaderFlags::GROUP_DESC);
    reader.skip(HeaderFlags::AUXTRACE);
    reader.skip(HeaderFlags::STAT);
    reader.skip(HeaderFlags::CACHE);
    if reader.has_more() {
        warn!("Unknown flags in header");
    }

    Ok(Info {
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
        cpu_topology,
    })
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
        let sections: Vec<PerfFileSection> =
            collect_n(bits_count(header.flags.bits()) as usize, || read_raw(file))?;
        debug!(
            "flags: {:x}, have {} info records, start at 0x{:x}",
            header.flags.bits(),
            sections.len(),
            header.data.offset + header.data.size
        );
        Ok(HeaderInfoReader {
            file: file,
            sections: sections,
            current: 0,
            flags: header.flags,
        })
    }

    fn seek(&mut self, flag: HeaderFlags) -> io::Result<()> {
        let section = &self.sections[self.current];
        debug!(
            "Read section {} {:?}, size {}",
            self.current, flag, section.size
        );
        self.file.seek(io::SeekFrom::Start(section.offset))?;
        self.current += 1;
        Ok(())
    }

    fn get_string(&mut self, flag: HeaderFlags) -> io::Result<Option<String>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.seek(flag)?;
            let size: u32 = read_raw(self.file)?;
            Ok(Some(read_string(self.file, size as usize)?))
        } else {
            Ok(None)
        }
    }

    fn get_string_array(&mut self, flag: HeaderFlags) -> io::Result<Option<Vec<String>>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.seek(flag)?;
            let count: u32 = read_raw(self.file)?;
            Ok(Some(collect_n(count as usize, || {
                let size: u32 = read_raw(self.file)?;
                read_string(self.file, size as usize)
            })?))
        } else {
            Ok(None)
        }
    }

    fn get_event_description(&mut self) -> io::Result<Option<Vec<EventDescription>>> {
        if self.flags.contains(HeaderFlags::EVENT_DESC) && self.sections.len() > self.current {
            self.seek(HeaderFlags::EVENT_DESC)?;
            let count: u32 = read_raw(self.file)?;
            let size: u32 = read_raw(self.file)?;
            debug!(" EVENT_DESC: count {}, size {}", count, size);
            let all_attributes = collect_n(count as usize, || {
                let attributes: EventAttributes = read_raw(self.file)?;
                self.file.seek(io::SeekFrom::Current(
                    size as i64 - mem::size_of::<EventAttributes>() as i64,
                ))?;
                let id_count: u32 = read_raw(self.file)?;
                let name_size: u32 = read_raw(self.file)?;
                let name = read_string(self.file, name_size as usize)?;
                let ids: io::Result<Vec<u64>> =
                    collect_n(id_count as usize, || read_raw(self.file)?);
                ids.map(|ids| EventDescription {
                    attributes,
                    name,
                    ids,
                })
            })?;
            Ok(Some(all_attributes))
        } else {
            Ok(None)
        }
    }

    fn get<T>(&mut self, flag: HeaderFlags) -> io::Result<Option<T>> {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            self.seek(flag)?;
            let v: T = read_raw(self.file)?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    fn skip(&mut self, flag: HeaderFlags) {
        if self.flags.contains(flag) && self.sections.len() > self.current {
            debug!(
                "Skip section {} {:?} size {}",
                self.current, flag, self.sections[self.current].size
            );
            self.current += 1;
        }
    }

    fn has_more(&self) -> bool {
        self.sections.len() > self.current
    }
}
