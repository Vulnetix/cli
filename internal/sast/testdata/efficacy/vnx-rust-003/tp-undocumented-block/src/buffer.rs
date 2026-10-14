pub fn zero_first(data: &mut Vec<u8>) {
    let ptr = data.as_mut_ptr();
~>    unsafe {
        *ptr.add(0) = 0;
    }
}
