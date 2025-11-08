pub trait SerializeField {
    fn field_to_binary(&self) -> Vec<u8>;
    fn field_def_to_binary(&self) -> Vec<u8>;
    fn from_binary_to_field(field_type: u16, field_name: String, value: Vec<u8>) -> Self;
}
