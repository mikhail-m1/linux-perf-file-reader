use std::{mem, io, slice, result};
use std::io::Read;

pub fn read_raw<T>(file: &mut Read) -> io::Result<T> {
    let size = mem::size_of::<T>();
    unsafe {
        let mut t: T = mem::uninitialized();
        let slice = slice::from_raw_parts_mut(mem::transmute(&mut t), size);
        file.read_exact(slice)?;
        Ok(t)
    }
}

pub fn read_string(file: &mut Read, size: usize) -> io::Result<String> {
    let mut buff = vec![0u8; size];
    file.read_exact(&mut buff)?;
    let end = buff.iter().position(|x| *x == 0).unwrap_or(buff.len());
    let s = String::from_utf8_lossy(&buff[0..end]).to_string();
    //debug!("read str max size:{}, result: {}, `{}`", size, s.len(), s);
    Ok(s)
}

pub fn collect_n<T, E, F>(count: usize, mut function: F) -> result::Result<Vec<T>, E>
    where F: FnMut() -> result::Result<T, E>
{
    let mut v = Vec::with_capacity(count);
    for _ in 0..count {
        v.push(function()?);
    }
    Ok(v)
}

