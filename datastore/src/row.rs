use field::pfield::Field;

#[derive(Clone)]
pub struct Row {
    pub row: Vec<Field>,
}

impl Row {
    pub fn new() -> Self {
        Self { row: Vec::new() }
    }

    pub fn add(&mut self, field: Field) {
        self.row.push(field);
    }

    pub fn get_field(&self, fieldname: &str) -> Option<Field> {
        for r in &self.row {
            if r.name == fieldname {
                return Some(r.clone());
            }
        }

        None
    }
}
