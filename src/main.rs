use rustpiboot::{boot, Options};

fn main() {
    simple_logger::SimpleLogger::new().env().init().unwrap();

    boot(Options::default()).unwrap();
}
