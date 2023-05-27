use md5::{Digest, Md5};
use std::collections::HashMap;
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

fn group_files_by_md5_hash(files: Vec<String>, files_by_hash: &mut HashMap<String, Vec<String>>) {
    for file in files {
        let file_hash = md5_hash(&file);
        if let Some(hashes) = files_by_hash.get_mut(&file_hash) {
            hashes.push(file);
        } else {
            files_by_hash.insert(file_hash, vec![file]);
        }
    }
}

fn list_files_in_directory(dir: &str) -> Vec<String> {
    let mut files = Vec::new();
    let read_dir = fs::read_dir(dir).unwrap();
    for result_entry in read_dir {
        let entry = result_entry.unwrap();
        if !entry.path().is_dir() {
            if let Some(path_str) = entry.path().to_str() {
                files.push(path_str.to_string().replace('\\', "/"))
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use std::{fs::File, str::from_utf8};

    use super::*;

    const CONTENT1: &str = "content #1\n";
    const CONTENT2: &str = "content #2\n";
    const CONTENT1_HASH: &str = "2afc33c9215e78de8066e5ea00fdd60c";
    const CONTENT2_HASH: &str = "b7bbfec474771efecb3e519d09c80fcc";

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

    #[test]
    fn group_files_by_md5_hash_creates_correct_groups() {
        // Setup
        let dir = "test_dir";
        fs::create_dir_all(dir).unwrap();
        let file1 = format!("{}/file1.txt", dir);
        let file2 = format!("{}/file2.txt", dir);
        let file3 = format!("{}/file3.txt", dir);
        let file4 = format!("{}/file4.txt", dir);
        fs::write(&file1, CONTENT1).unwrap();
        fs::write(&file2, CONTENT1).unwrap();
        fs::write(&file3, CONTENT2).unwrap();
        fs::write(&file4, CONTENT1).unwrap();

        // Test
        let mut files_by_hash = HashMap::new();
        group_files_by_md5_hash(
            vec![file1.clone(), file2.clone(), file3.clone(), file4.clone()],
            &mut files_by_hash,
        );

        // Assertions
        assert_eq!(files_by_hash.len(), 2);
        let group1 = files_by_hash.get(CONTENT1_HASH).unwrap();
        assert_eq!(group1.len(), 3);
        assert!(group1.contains(&file1));
        assert!(group1.contains(&file2));
        assert!(group1.contains(&file4));
        let group2 = files_by_hash.get(CONTENT2_HASH).unwrap();
        assert_eq!(group2.len(), 1);
        assert!(group2.contains(&file3));

        // Teardown
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_files_in_directory_returns_vector_with_file_names() {
        // Setup
        let dir = "test_dir";
        let sub = format!("{}/sub", dir);
        fs::create_dir_all(sub).unwrap();
        let file1 = format!("{}/file1.txt", dir);
        let file2 = format!("{}/file2.txt", dir);
        fs::write(&file1, CONTENT1).unwrap();
        fs::write(&file2, CONTENT2).unwrap();

        // Test
        let files: Vec<String> = list_files_in_directory(dir);

        // Assertions
        assert_eq!(files.len(), 2);
        assert!(&files.contains(&file1));
        assert!(&files.contains(&file2));

        // Teardown
        fs::remove_dir_all(dir).unwrap();
    }
}
