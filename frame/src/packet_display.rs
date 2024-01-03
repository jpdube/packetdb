pub trait PacketDisplay {
    fn summary(&self) -> String;
    fn show_detail(&self) -> String;
}
