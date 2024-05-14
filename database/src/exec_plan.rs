extern crate chrono;
use std::collections::VecDeque;

use chrono::Local;
use chrono::{prelude::*, Duration};
// use std::time::SystemTime;

#[derive(Debug, Clone)]
struct PlanEntry {
    description: String,
    exec_time: DateTime<Local>,
    delta: Duration,
}
impl Default for PlanEntry {
    fn default() -> Self {
        Self {
            description: String::new(),
            exec_time: Local::now(),
            delta: Duration::milliseconds(0),
        }
    }
}

impl PlanEntry {
    pub fn show(&self) -> String {
        let mut delta: String = String::new();

        if let Some(offset) = self.delta.num_microseconds() {
            if offset > 1000 {
                delta = format!("{}ms", offset / 1000);
            } else {
                delta = format!("{}us", offset);
            }
        }

        format!(
            "{}: at: {} duration: {}",
            self.description,
            self.exec_time.format("%Y-%m-%d %H:%M:%S"),
            delta
        )
    }
}

#[derive(Default, Clone, Debug)]
pub struct ExecutionPlan {
    lines: Vec<PlanEntry>,
    pql: String,
    active_list: VecDeque<PlanEntry>,
}

impl ExecutionPlan {
    pub fn start(&mut self, description: &str) {
        let current = PlanEntry {
            description: description.to_string(),
            exec_time: Local::now(),
            delta: Duration::milliseconds(0),
        };

        self.active_list.push_front(current);
    }

    pub fn stop(&mut self) {
        if let Some(mut current) = self.active_list.pop_front() {
            current.delta = Local::now() - current.exec_time;
            self.lines.push(current.clone());
        }
    }

    // pub fn add(&mut self, description: &str) {
    //     let mut entry = PlanEntry {
    //         description: description.to_string(),
    //         exec_time: Local::now(),
    //         delta: Duration::milliseconds(0),
    //     };

    //     if self.lines.len() > 0 {
    //         let last_plan = &self.lines[self.lines.len() - 1];
    //         entry.delta = entry.exec_time - last_plan.exec_time;
    //     }

    //     self.lines.push(entry);
    // }

    pub fn set_pql(&mut self, pql: &str) {
        self.pql = pql.to_string();
    }

    pub fn show(&mut self) {
        println!("------------------------------------------------");
        println!("Execution plane for: {}", self.pql);
        println!("------------------------------------------------");
        let mut total: i64 = 0;
        for (index, line) in self.lines.iter().enumerate() {
            println!("{}: {}", index, line.show());
            total += line.delta.num_milliseconds();
        }

        println!("------------------------------------------------");
        println!("Total time: {}ms", total);
    }
}
