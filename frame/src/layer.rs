use dyn_clone::DynClone;

pub trait Layer: DynClone {
    fn get_name(&self) -> String;
    fn get_field(&self, field_name: u32) -> usize;
    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>>;
}
