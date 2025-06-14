use derive_more::From;
use regex;
use reqwest::blocking as req;
use scraper::{Html, Selector};
use std::{
    env::current_dir,
    fmt::Display,
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::Duration,
};
use zip_extract;

#[derive(Debug, From)]
enum Error {
    ReqwestError(reqwest::Error),
    ParsingError(scraper::error::SelectorErrorKind<'static>),
    IOError(std::io::Error),
    ZipExtractError(zip_extract::ZipExtractError),
    GenericError(Box<dyn std::error::Error>),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ReqwestError(error) => write!(f, "{error:?}"),
            Error::ParsingError(selector_error_kind) => write!(f, "{selector_error_kind:?}"),
            Error::IOError(error) => write!(f, "{error:?}"),
            Error::ZipExtractError(zip_extract_error) => write!(f, "{zip_extract_error:?}"),
            Error::GenericError(error) => write!(f, "{error:?}"),
        }
    }
}

type Result<T> = core::result::Result<T, Error>;

fn check_game_directory() -> Result<bool> {
    println!("Checking current directory: {:?}", current_dir()?);
    let game_path = Path::new(r"\steamapps\common\Granblue Fantasy Versus Rising").to_str();
    return Ok(current_dir()?
        .to_str()
        .unwrap()
        .contains(game_path.unwrap()));
}

fn get_latest_version() -> Result<String> {
    let url = "https://github.com/agersant/gbvsr-frame-meter/releases/latest";
    let html = Html::parse_document(req::get(url)?.text()?.as_str());
    let selector = Selector::parse("title")?;
    let reg = regex::Regex::new(r"\d+\.\d+.\d+").unwrap();
    let version = html
        .select(&selector)
        .find_map(|ele| {
            let version = ele
                .text()
                .find_map(|text| reg.captures(text))
                .expect("No valid version found");
            Some(version.get(0).expect("No valid version found"))
        })
        .expect("No valid version found")
        .as_str()
        .to_string();

    println!("Latest Version: {:?}", version);
    Ok(version)
}

fn check_current_version() -> Result<String> {
    let path = current_dir()?.join("frame_meter.ver");
    if let Ok(mut file) = File::open(path) {
        let mut buf = String::new();
        file.read_to_string(&mut buf)?;
        println!("Current version: {:?}", &buf);
        return Ok(buf);
    } else {
        println!("No current version found");
        return Ok("".to_string());
    }
}

fn get_link(version: &String) -> Result<String> {
    let url = "https://github.com/agersant/gbvsr-frame-meter/releases/expanded_assets";
    let version_url = format!("{}/{}", url, version);
    let html = Html::parse_document(req::get(version_url)?.text()?.as_str());
    let selector = Selector::parse("[href]")?;
    let hash = html
        .select(&selector)
        .find_map(|item| {
            item.value().attrs().find_map(|(name, value)| {
                if name == "href" && value.contains("download") && value.contains(".zip") {
                    return Some(value);
                }
                None
            })
        })
        .expect("No download link found");
    let link = format!("https://github.com{}", hash);
    println!("Download Link: {:?}", link);
    Ok(link)
}

fn download_file(link: &String) -> Result<Vec<u8>> {
    let mut res = req::get(link)?;
    let mut buf: Vec<u8> = vec![];
    res.copy_to(&mut buf)?;
    println!("download file: {:?} bytes", &buf.len());
    Ok(buf)
}

fn extract_file(buf: Vec<u8>, version: &String) -> Result<()> {
    // r"RED\Binaries\Win64"
    let extract_directory = current_dir()?.join(PathBuf::from(r"RED\Binaries\Win64"));
    zip_extract::extract(Cursor::new(buf), &extract_directory, true)?;
    println!("Extract directory: {:?}", extract_directory);
    let mut file = File::create(current_dir()?.join(r"frame_meter.ver"))?;
    file.write(version.as_bytes())?;
    Ok(())
}

fn hide_console_window() {
    use std::ptr;
    use winapi::um::wincon::GetConsoleWindow;
    use winapi::um::winuser::{ShowWindow, SW_HIDE};

    let window = unsafe { GetConsoleWindow() };
    // https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
    if window != ptr::null_mut() {
        unsafe {
            ShowWindow(window, SW_HIDE);
        }
    }
}

fn open_game() -> Result<()> {
    println!("Opening game");
    let env_exe = std::env::current_exe()?;
    let game = current_dir()?
        .read_dir()?
        .find_map(|entry| {
            if let Err(_) = entry {
                return None;
            }
            let path = entry.unwrap().path();
            if path.to_str()? != env_exe.to_str()? && path.to_str()?.contains(".exe") {
                Some(path)
            } else {
                None
            }
        })
        .expect("Game executable not found");
    sleep(Duration::from_secs(2));
    hide_console_window();
    Command::new(game).output()?;
    Ok(())
}

fn main() -> Result<()> {
    if !check_game_directory()? {
        println!("Executable not on game directory");
        sleep(Duration::from_secs(2));
        return Ok(());
    }

    println!("Updating Frame Meter Mod");
    let version = get_latest_version()?;
    if version != check_current_version()? {
        let download_link = get_link(&version)?;
        let file = download_file(&download_link)?;
        extract_file(file, &version)?;
        println!("Mod updated!");
    }

    open_game()?;
    Ok(())
}
