#![allow(unused)]
use std::{fs, path, io, time, thread};
use std::io::{stdout, Write, BufReader, BufRead};
use std::process::{Command, Stdio};
use std::time::Duration;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::fs::File;
use std::io::prelude::*;
use clap::{AppSettings, ArgEnum, Parser};
use crossterm::{
    ExecutableCommand, execute, Result,
    cursor::{Hide, Show, RestorePosition, SavePosition}
};
use crate::time::Instant;
use sha256::digest_file;
use which::which;


/// run stegseek on every file in a directory
#[derive(Parser)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
#[clap(name = "steghunt")]
#[clap(author = "@quicktus")]
#[clap(version = "1.0")]
#[clap(about = "Automated bulk detection and cracking of files hidden using steghide.", long_about = None)]
#[clap(propagate_version = true)]

struct Cli {
    /// Mode to use
    #[clap(arg_enum, value_parser)]
    mode: Mode,

    /// Path to the directory containing the images that will be processed
    #[clap(short = 'i', long = "input", parse(from_os_str))]
    in_path: std::path::PathBuf,

    /// Path to the directory where cracked files will be stored (does not need to exist)
    #[clap(short = 'o', long = "output", parse(from_os_str))]
    out_path: std::path::PathBuf,

    /// Recursively search subdirectories
   #[clap(short = 'r', long = "recursive", parse(from_occurrences))]
    recursive: u8,

    /// Skip duplicate images
    #[clap(short = 'd', long = "dupeskip", parse(from_occurrences))]
    dupe_skip: u8,

    /// Skip images below this size in Bytes
    #[clap(short = 'm', long = "minsize", default_value_t = 1024)]
    min_size: u32,

    /// Path to the wordlist to use for cracking
    #[clap(short = 'w', long = "wordlist", parse(from_os_str))]
    wordlist_path: Option<std::path::PathBuf>,

    /// Don't print stats
    #[clap(short = 'q', long = "quiet", parse(from_occurrences))]
    quiet: u8,

}


#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ArgEnum)]
#[allow(non_camel_case_types)]
enum Mode {
    seed,
    crack,
    seedcrack,
}


fn main() {
    let args = Cli::parse();

    let wordlist = match args.wordlist_path {
        Some(x) => x,
        None => PathBuf::new(),
    };
    let dupe_skip: bool = (args.dupe_skip == 1);
    let recursive: bool = (args.recursive == 1);
    let quiet: bool = (args.quiet == 1);

    if which("stegseek").is_err() {
        println!("stegseek is not installed. exiting.");
        return;
    }

    if ! quiet {
        execute!(
            stdout(),
            SavePosition,
            Hide
        );
        println!("\nInitializing ...");
        execute!(
            stdout(),
            RestorePosition
        );
    }

    let mut hashes = Vec::new();
    let file_list = get_files(&args.in_path, &mut hashes, args.min_size, dupe_skip, recursive);

    let mut files_total: i32 = file_list.len().try_into().unwrap();
    let mut files_processed = 0;
    let mut files_found = 0;
    let mut files_cracked = 0;

    File::create("steghunt_log");
    let mut log_file = fs::OpenOptions::new()
      .write(true)
      .append(true)
      .open("steghunt_log")
      .unwrap();
      
    if args.mode != Mode::seed {
        fs::create_dir_all(args.out_path.clone());
    }

    if ! quiet { 
        print_stats(0, files_processed, files_total,  files_found, files_cracked, args.mode);
    }

    let from_time = Instant::now();

    for steg_file in file_list {

        let str_path = steg_file.clone().into_os_string().into_string().unwrap();

        if args.mode == Mode::seed {
            let mut cmd = Command::new("stegseek")
                                 .arg("--seed")
                                 .arg("-a")
                                 .arg("-q")
                                 .arg("-sf").arg(steg_file)
                                 .stdout(Stdio::piped())
                                 .stderr(Stdio::piped())
                                 .spawn()
                                 .unwrap();

            let stderr = cmd.stderr.as_mut().unwrap();
            let stderr_reader = BufReader::new(stderr);
            let stderr_lines = stderr_reader.lines();
            let mut err_no_seed = false;

            for line in stderr_lines {
                if line.unwrap().contains("error:") { //  Could not find a valid seed.
                err_no_seed = true;
                }
            }
            if !err_no_seed {
                files_found += 1;
                write!(log_file, "{}\n", str_path);
            }
                
            cmd.wait();
        }
    
        else if args.mode == Mode::crack {
            let mut cmd = Command::new("stegseek")
                                 .arg("--crack")
                                 .arg("-a")
                                 .arg("-f")
                                 .arg("-q")
                                 .arg("-wl").arg(&wordlist)
                                 .arg("-sf").arg(steg_file.clone())
                                 .arg("-xf").arg(&args.out_path.join(steg_file.file_name().unwrap().to_str().unwrap().to_owned() + ".out"))
                                 .stdout(Stdio::piped())
                                 .stderr(Stdio::piped())
                                 .spawn()
                                 .unwrap();

            let stderr = cmd.stderr.as_mut().unwrap();
            let stderr_reader = BufReader::new(stderr);
            let stderr_lines = stderr_reader.lines();
            let mut err_no_crack = false;

            for line in stderr_lines {
                if line.unwrap().contains("error:") { // Could not find a valid passphrase.
                err_no_crack = true;
                }
            }
            if !err_no_crack {
                files_cracked += 1;
            }
            
            cmd.wait();
        }
    
        else if args.mode == Mode::seedcrack {
            let mut cmd = Command::new("stegseek")
                                 .arg("--seed")
                                 .arg("-a")
                                 .arg("-q")
                                 .arg("-sf").arg(steg_file.clone())
                                 .stdout(Stdio::piped())
                                 .stderr(Stdio::piped())
                                 .spawn()
                                 .unwrap();

            let stderr = cmd.stderr.as_mut().unwrap();
            let stderr_reader = BufReader::new(stderr);
            let stderr_lines = stderr_reader.lines();
            let mut err_no_seed = false;

            for line in stderr_lines {
                if line.unwrap().contains("error:") {
                    err_no_seed = true;
                }
            }
            if !err_no_seed {
                files_found += 1;
                write!(log_file, "{}\n", str_path);
                
                // crack
                    let mut cmd = Command::new("stegseek")
                                    .arg("--crack")
                                    .arg("-a")
                                    .arg("-f")
                                    .arg("-q")
                                    .arg("-wl").arg(&wordlist)
                                    .arg("-sf").arg(steg_file.clone())
                                    .arg("-xf").arg(&args.out_path.join(steg_file.file_name().unwrap().to_str().unwrap().to_owned() + ".out"))
                                    .stdout(Stdio::piped())
                                    .stderr(Stdio::piped())
                                    .spawn()
                                    .unwrap();

                    let stderr = cmd.stderr.as_mut().unwrap();
                    let stderr_reader = BufReader::new(stderr);
                    let stderr_lines = stderr_reader.lines();
                    let mut err_no_crack = false;

                    for line in stderr_lines {
                        if line.unwrap().contains("error:") { // Could not find a valid passphrase.
                            err_no_crack = true;
                        }
                    }
                    if !err_no_crack {
                        files_cracked += 1;
                    }
                
            }
            
            cmd.wait();
        }
        
        files_processed += 1;
        let time_diff = from_time.elapsed().as_secs();
   
        if ! quiet {
            execute!(
                stdout(),
                RestorePosition
            );
            print_stats(time_diff, files_processed, files_total,  files_found, files_cracked, args.mode);
        }
        
    }

    if ! quiet {
        if files_found == 0 && files_cracked == 0 {
            println!("Encryption can break your heart sometimes.");
        }
        execute!(
            stdout(),
            Show
        );
    }

}

fn get_files(dir_name: &path::PathBuf, hashes: &mut Vec<String>, min_size: u32, dupe_skip: bool, recursive: bool) -> Vec<path::PathBuf> {

    let mut file_list: Vec<path::PathBuf> = Vec::new();

    for entry in fs::read_dir(dir_name).unwrap() {
        let entry = entry.unwrap();
        let meta = entry.metadata().unwrap();
        let path = entry.path();

        if meta.is_file() {
            // check file size
            if meta.len() >= min_size.into() {
                // check magic number
                let mut b = Vec::<u8>::with_capacity(4);
                let f = match File::open(&path) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                f.take(4).read_to_end(&mut b);
                if (b[0] == 0x42 && b[1] == 0x4d) ||     // bitmap
                   (b[0] == 0xFF && b[1] == 0xD8) ||     // jpeg
                   b == vec![0x2e, 0x73, 0x6e, 0x64] ||  // au
                   b == vec![0x52, 0x49, 0x46, 0x46] {   // wav
                    // skip duplicates
                    if dupe_skip == true {
                        let hash = digest_file(&path).unwrap();
                        if ! hashes.contains(&hash) {
                            file_list.push(path);
                            (*hashes).push(hash);
                        }
                    }
                    else {
                        file_list.push(path);
                    }
                }
            }
        }
        
        else if meta.is_dir() && recursive == true {
            file_list.append(&mut get_files(&path, hashes, min_size, dupe_skip, recursive));
        }
    }
    return file_list;
}

fn print_stats (t: u64, fp: i32, ft: i32,  ff: i32, fc: i32, mode: Mode) {
    let divider = "-".repeat(42);

    let h = t / 3600;
    let m = t % 3600 / 60;
    let s = t % 60;

    println!("\n{}", divider);
    println!("files processed: {} out of {} ({:.1}%)", fp, ft, (100 * fp / ft));
    println!("duration: {:02}:{:02}:{:02}", h, m, s);
    
    if mode == Mode::seed || mode == Mode::seedcrack {
        println!("(possible) stegfiles detected: {}", ff);
    }

    if mode == Mode::crack || mode == Mode::seedcrack {
    println!("stegfiles cracked: {}", fc);
    }

    println!("{}\n", divider);
    io::stdout().flush().unwrap();
}