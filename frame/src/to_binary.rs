pub trait ToBinary {
    fn field_to_binary(&self) -> Vec<u8>;
    fn field_def_to_binary(&self) -> Vec<u8>;
}
