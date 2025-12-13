use dyn_clone::DynClone;
use field::pfield::Field;

pub trait Layer: DynClone {
    fn get_name(&self) -> String;
    fn get_field(&self, field_name: &str) -> Option<Field>;
    fn get_field_bytes(&self, _field_name: String) -> Option<Vec<u8>>;
}
