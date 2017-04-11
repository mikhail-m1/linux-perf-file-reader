#[macro_use] 
extern crate log;
extern crate linux_perf_file_reader;
extern crate env_logger;
#[allow(unused_imports)]

macro_rules! print_if_some_child {
    ($format: expr, $parent: expr, $($field: tt),*) => {
        $(if $parent.$field.is_some() {
            print!($format, stringify!($field), $parent.$field.as_ref().unwrap());
        })*
    };
}

macro_rules! print_if_some {
    ($format: expr, $($field: tt),*) => {
        $(if $field.is_some() {
            print!($format, stringify!($field), $field.as_ref().unwrap());
        })*
    };
}

fn main() {
    env_logger::init().unwrap();
    use linux_perf_file_reader::Event;
    let args: Vec<String> = std::env::args().collect();
    match linux_perf_file_reader::read_perf_file(args.get(1).expect("use with perf.data file in command line")) {
        Err(e) => {
            error!("Error: {}", e);
            for e in e.iter().skip(1) {
                error!("caused by: {}", e);
            }
            std::process::exit(-1);
        }
        Ok(ref perf) => {
            println!("Info:");
            print_if_some_child!(" {}: {}\n", perf.info, hostname, os_release, tools_version, arch, cpu_description, cpu_id, total_memory);
            print_if_some_child!(" {}: {:?}\n", perf.info, command_line, cpu_topology, cpu_count);
            if let Some(ref event_description) = perf.info.event_description {
                for d in event_description {
                    println!(" event_attribute {}{:?}: {:?}", d.name, d.ids, d.attributes);
                }
            }
            println!("\nAttrs:");
            for attr in perf.event_attributes.iter() {
                println!(" {:?}", attr);
            }

            println!("\nEvents:");
            for event in perf.events.iter() {
                match event {
                    &Event::MMap{pid, tid, addr, len, pgoff, ref filename, ref sample_id} => {
                        println!(" Mmap: pid: {}, tid: {}, addr: {:x}, len: {}, pgoff: {:x} - {}", pid, tid, addr, len,  pgoff, filename);
                        print_sample_id(sample_id);
                    },
                    &Event::MMap2{pid, tid, addr, len, pgoff, maj, min, ino, ino_generation, prot, flags, ref filename, ref sample_id} => {
                        println!(" Mmap2: pid: {}, tid: {}, addr: {:x}, len: {}, pgoff: {:x} - {}", pid, tid, addr, len,  pgoff, filename);
                        println!("   dev: {}:{} inode: {}, inode generation: {}, prot: {}, flags: {}", maj, min, ino, ino_generation, prot, flags);
                        print_sample_id(sample_id);
                    }
                    &Event::Exit{pid, ppid, tid, ptid, time, ref sample_id} => {
                        println!(" Exit: pid: {}, ppid: {}, tid:{}, ptid: {}, time: {}", pid, ppid, tid, ptid, time);
                        print_sample_id(sample_id);
                    },
                    &Event::Comm{pid, tid, ref comm, ref sample_id} => {
                        println!(" Comm: pid: {}, tid:{}, comm: {}", pid, tid, comm);
                        print_sample_id(sample_id);
                    },
                    &Event::Sample{identifier, ip, pid, tid, time, addr, id, stream_id, cpu, res, period, ref call_chain} => {
                        print!(" Sample:");
                        print_if_some!(" {}: {:x}", ip, addr);
                        print_if_some!(" {}: {}", pid, tid, time, id, identifier, stream_id, cpu, res, period);
                        println!("");
                        if !call_chain.is_empty() {
                            println!("  call chain: {:?}", call_chain);
                        }
                    },
                    &Event::FinishedRound => {}
                    &Event::Unsupported => {}
                }
            }
        }
    }
}

fn print_sample_id(sample_id: &linux_perf_file_reader::SampleId) {
    print!("  Sample:");
    print_if_some_child!(" {}: {}", sample_id, pid, tid, time, id, stream_id, cpu, res, identifier);
    println!("");
}
