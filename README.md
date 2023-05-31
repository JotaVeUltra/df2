# Duplicate File Finder

This program is a command-line tool written in Rust that helps you find duplicate files within one or more directories. It uses the MD5 hash algorithm to compare the contents of files and identify duplicates.

## Usage

To run the program, use the following command:

```
df2 <path>...
```

Replace `<path>...` with one or more directory paths that you want to search for duplicate files in.

## Options

The program supports the following options:

- `-h`, `--help`: Displays the usage information and options.
- `-q`, `--quiet`: Runs the program in quiet mode, suppressing all output except for the final results.

## Prerequisites

Make sure you have [Rust](https://www.rust-lang.org/) installed on your system.

## Installation

1. Clone this repository or download the source code.
2. Navigate to the project directory in your terminal.
3. Build the project using the following command:

```shell
cargo build --release
```

4. The compiled binary will be available in the `target/release` directory.

## Example

```
$ ./df2 /path/to/directory1 /path/to/directory2

Computing duplicates in the following directories:
- /path/to/directory1
- /path/to/directory2

Duplicates found:

Hash: 5f4dcc3b5aa765d61d8327deb882cf99
Files:
- /path/to/directory1/file1.txt
- /path/to/directory2/file2.txt

Hash: 098f6bcd4621d373cade4e832627b4f6
Files:
- /path/to/directory1/file3.txt
- /path/to/directory2/file4.txt
- /path/to/directory2/file5.txt
```

## Running tests

```shell
cargo test -- --test-threads=1
```
