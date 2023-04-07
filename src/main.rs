use std::io::Write;
use std::path::Path;
use std::{env, io};

const USAGE_TEXT: &[u8] = b"Usage:\n    df2 <path>...\n";
const OPTIONS_TEXT: &[u8] = b"\nOptions:\n    -h --help\n";

fn main() {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    let args: Vec<String> = env::args().collect();
    handle(&mut writer, args);
}

fn handle<W: Write>(writer: &mut W, args: Vec<String>) {
    if args.len() < 2 {
        return write_output(writer, vec![USAGE_TEXT]);
    }
    if args.contains(&String::from("-h")) || args.contains(&String::from("--help")) {
        return write_output(writer, vec![USAGE_TEXT, OPTIONS_TEXT]);
    }
    for arg in args.iter().skip(1) {
        let path = Path::new(arg);
        if !path.exists() {
            return write_output(
                writer,
                vec![b"Error: Directory ", arg.as_bytes(), b" does not exist.\n"],
            );
        } else if !path.is_dir() {
            return write_output(
                writer,
                vec![b"Error: ", arg.as_bytes(), b" is not a directory.\n"],
            );
        }
    }
}

fn write_output<W: Write>(writer: &mut W, texts: Vec<&[u8]>) {
    for text in texts.iter() {
        writer.write_all(text).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        str::from_utf8,
    };

    use super::*;

    #[test]
    fn handle_writes_usage_text_if_no_arguments_passed() {
        // Setup
        let mut buf = Vec::new();
        let args: Vec<String> = vec![String::from("bin")];

        // Test
        handle(&mut buf, args);
        let out = from_utf8(&buf).unwrap();

        // Assertions
        assert_eq!(from_utf8(USAGE_TEXT).unwrap(), out);
    }

    #[test]
    fn handle_writes_usage_and_options_text_if_help_option_passed() {
        // Setup
        let mut buf = Vec::new();
        let args: Vec<String> = vec![String::from("bin"), String::from("--help")];

        // Test
        handle(&mut buf, args);
        let out = from_utf8(&buf).unwrap();

        // Assertions
        assert_eq!(
            from_utf8(&[USAGE_TEXT, OPTIONS_TEXT].concat()).unwrap(),
            out
        );
    }

    #[test]
    fn handle_writes_error_message_if_directory_does_not_exist() {
        // Setup
        let mut buf = Vec::new();
        let args: Vec<String> = vec![String::from("bin"), String::from("nonexistent_dir")];

        // Test
        handle(&mut buf, args);
        let out = from_utf8(&buf).unwrap();

        // Assertions
        assert!(out.contains("Error: Directory nonexistent_dir does not exist.\n"));
    }

    #[test]
    fn handle_writes_error_message_if_argument_is_not_a_directory() {
        // Setup
        let mut buf = Vec::new();
        let file_path = "file.txt";
        let args: Vec<String> = vec![String::from("bin"), String::from(file_path)];
        File::create(file_path).unwrap();

        // Test
        handle(&mut buf, args);
        let out = from_utf8(&buf).unwrap();

        // Assertions
        let expected_output = format!("Error: {} is not a directory.\n", file_path);
        assert_eq!(expected_output, out);

        // Teardown
        fs::remove_file(file_path).unwrap();
    }
}
