use md5::{Digest, Md5};
use std::io::Write;
use std::path::Path;
use std::{env, fs, io};
use walkdir::WalkDir;

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
    let mut dirs: Vec<String> = Vec::new();
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
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.path().is_dir() {
                if let Some(v) = entry.path().to_str() {
                    dirs.push(v.to_string().replace('\\', "/"))
                }
            }
        }
    }
    write_output(
        writer,
        vec![b"Computing duplicates in the following directories:\n"],
    );
    for dir in dirs.iter() {
        write_output(writer, vec![b"- ", dir.as_bytes(), b"\n"]);
    }
    write_output(writer, vec![b"\nNo duplicate files found\n"]);
}

fn write_output<W: Write>(writer: &mut W, texts: Vec<&[u8]>) {
    for text in texts.iter() {
        writer.write_all(text).unwrap();
    }
}

fn md5_hash(file_name: &str) -> String {
    let file_bytes = fs::read(file_name).expect("Failed to read file");
    let mut hasher = Md5::new();
    hasher.update(&file_bytes);
    let result = hasher.finalize();
    format!("{:x}", result)
}

#[cfg(test)]
mod tests {
    use std::{fs::File, str::from_utf8};

    use super::*;

    const CONTENT1: &str = "content #1\n";
    const CONTENT1_HASH: &str = "2afc33c9215e78de8066e5ea00fdd60c";

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

    #[test]
    fn handle_writes_directories_computed() {
        // Setup
        let dir = "test_dir";
        let sub = format!("{}/test_subdir", dir);
        fs::create_dir_all(&sub).unwrap();
        let mut buf = Vec::new();
        let args: Vec<String> = vec![String::from("bin"), dir.to_string()];

        // Test
        handle(&mut buf, args);
        let out = from_utf8(&buf).unwrap();

        // Assertions
        assert!(out.contains(&format!(
            "Computing duplicates in the following directories:\n- {}\n- {}",
            dir, sub
        )));

        // Teardown
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn handle_writes_no_duplicates_message_if_no_duplicates_found() {
        // Setup
        fs::create_dir_all("empty_dir").unwrap();
        let mut buf = Vec::new();
        let args: Vec<String> = vec![String::from("bin"), String::from("empty_dir")];

        // Test
        handle(&mut buf, args);
        let out = from_utf8(&buf).unwrap();

        // Assertions
        assert!(out.contains("No duplicate files found"));

        // Teardown
        fs::remove_dir_all("empty_dir").unwrap();
    }

    #[test]
    fn md5_hash_calculates_correct_hash_for_file() {
        // Setup
        let file_name = "test_file.txt";
        fs::write(file_name, CONTENT1).unwrap();

        // Test
        let actual_hash = md5_hash(file_name);

        // Assertions
        assert_eq!(CONTENT1_HASH, actual_hash);

        // Teardown
        fs::remove_file(file_name).unwrap();
    }
}
