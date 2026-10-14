pub struct Handle(*mut u8);

~>unsafe impl Send for Handle {}
~>unsafe impl Sync for Handle {}
