#![feature(async_closure)]
#![feature(result_map_or_else)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate sc;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate slog;
#[macro_use]
extern crate tokio;

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::Metadata;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use clap::arg_enum;
use exit::{Exit, ExitDisplay};
use futures::stream::{self, Stream, StreamExt, TryStreamExt};
use rand::{thread_rng, Rng};
use regex::bytes::Regex; // NOTE: &[u8] Regex, not &str
use serde::de::{self, Deserialize};
use slog::{Drain, LevelFilter};
use slog_async;
use slog_scope_futures::FutureExt;
use slog_stdlog;
use slog_term;
use snafu::{OptionExt, ResultExt, Snafu};
use structopt::StructOpt;
use tokio::{fs, io, process::Command, runtime::Builder, sync::mpsc, task};

// NOTE list:
// - If someone ever wants to implement Windows support, they'll likely need to use the
// remove_dir_all crate due to https://github.com/rust-lang/rust/issues/29497

// TODO Chuck the tempdir in the ReifiedConfig as well
// TODO Check for presence of a config file in the 'source' directory, prefer it above the XDG
// config file

const TMP_DIR_NAME: &str = ".harmonise_tmp";
const TMP_FILE_RETRIES: usize = 8;
const QUEUE_BUFFER: usize = 1024;

// Command-line options {{{
#[derive(Debug, StructOpt)]
#[structopt(
    name = "Harmonise",
    about = "Utility to prepare a music library for use on an Android phone"
)]
struct Opt {
    /// Log level.
    #[structopt(short, long, default_value = "info")]
    log_level: LogLevel,

    /// The source directory to transcode/copy files *from*.
    ///
    /// Required if not specified in the configuration file. Overrides any specified in the
    /// configuration file.
    #[structopt(short, long, parse(from_os_str))]
    source: Option<PathBuf>,

    /// The output directory to transcode/copy files *to*.
    ///
    /// Required if not specified in the configuration file. Overrides any specified in the
    /// configuration file.
    #[structopt(short, long, parse(from_os_str))]
    output: Option<PathBuf>,

    /// The config file to use, instead of the default.
    #[structopt(short, long, parse(from_os_str))]
    config_file: Option<PathBuf>,
}

arg_enum! {
    #[derive(Clone, Copy, Debug)]
    enum LogLevel {
        Debug,
        Info,
        Warning,
        Error,
        Critical
    }
}

impl Into<slog::Level> for LogLevel {
    fn into(self) -> slog::Level {
        match self {
            LogLevel::Debug => slog::Level::Debug,
            LogLevel::Info => slog::Level::Info,
            LogLevel::Warning => slog::Level::Warning,
            LogLevel::Error => slog::Level::Error,
            LogLevel::Critical => slog::Level::Critical,
        }
    }
}
// }}}

// Configuration {{{
#[derive(Debug)]
struct ReifiedConfig {
    source: PathBuf,
    output: PathBuf,
    music_filetypes: HashSet<OsString>,
    lossy_filetypes: HashSet<OsString>,
    nice: ConfigNice,
    ionice: ConfigIoNice,
    replace_pattern: Regex,
}

impl ReifiedConfig {
    fn from(c: Config) -> Result<Self, Error> {
        let music_filetypes: HashSet<OsString> = c
            .lossless_filetypes
            .union(&c.lossy_filetypes)
            .map(|s| s.clone())
            .collect();
        Ok(Self {
            source: c.source.context(ConfigNoSource)?,
            output: c.output.context(ConfigNoOutput)?,
            music_filetypes,
            lossy_filetypes: c.lossy_filetypes,
            nice: c.nice,
            ionice: c.ionice,
            replace_pattern: c.replace_pattern,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct Config {
    // TODO Allow ~ paths in the config file? Support other shell expansions?
    // Doing this optimally would require https://github.com/serde-rs/serde/issues/723 to be
    // resolved
    source: Option<PathBuf>,
    output: Option<PathBuf>,
    lossless_filetypes: HashSet<OsString>,
    lossy_filetypes: HashSet<OsString>,
    nice: ConfigNice,
    ionice: ConfigIoNice,
    #[serde(with = "serde_regex")]
    replace_pattern: Regex,
}

#[derive(Debug, Deserialize)]
struct ConfigNice {
    enable: bool,
    #[serde(deserialize_with = "nice_level_in_range")]
    level: i8,
}

#[derive(Debug, Deserialize)]
struct ConfigIoNice {
    enable: bool,
    level: IoPrioValue,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            source: None,
            output: None,
            lossless_filetypes: LOSSLESS_FILETYPES.clone(),
            lossy_filetypes: LOSSY_FILETYPES.clone(),
            nice: ConfigNice {
                enable: true,
                level: 19,
            },
            ionice: ConfigIoNice {
                enable: true,
                level: IoPrioValue::BestEffort(7),
            },
            replace_pattern: ANDROID_UNSAFE_PATTERN.clone(),
        }
    }
}
fn nice_level_in_range<'de, D>(d: D) -> Result<i8, D::Error>
where
    D: de::Deserializer<'de>,
{
    let val: i8 = Deserialize::deserialize(d)?;

    if val < NICE_MIN || val > NICE_MAX {
        Err(de::Error::invalid_value(
            de::Unexpected::Signed(val as i64),
            &"a number between -20 and 19, inclusive",
        ))
    } else {
        Ok(val)
    }
}
const NICE_MAX: i8 = 19;
const NICE_MIN: i8 = -20;
// }}}

// Can be overridden by configuration file
lazy_static! {
    static ref LOSSLESS_FILETYPES: HashSet<OsString> = vec!["ape", "flac", "wav"]
        .into_iter()
        .map(OsString::from)
        .collect();
    static ref LOSSY_FILETYPES: HashSet<OsString> = vec!["mp3", "m4a", "vob", "wma", "ogg"]
        .into_iter()
        .map(OsString::from)
        .collect();

    // On at least some Android sd cards (exfat), the following characters are invalid in
    // filenames: ?:"*|\<>
    static ref ANDROID_UNSAFE_PATTERN: Regex = Regex::new(r#"[?:"*|\\<>]"#)
        .expect("Build statically defined regex");
}

fn main() -> Exit<Error> {
    let opt = Opt::from_args();
    let _guard = setup_logging(&opt);
    let log = slog_scope::logger().new(o!("scope" => "main"));
    let config = build_config(&opt)?;
    let config = ReifiedConfig::from(config)?;

    // Change process IO priority before we create threads
    if config.ionice.enable {
        lower_own_io_priority(&config)?;
    };

    // NOTE: We effectively split the usage of these threads into three:
    // - One third are used for running ffmpeg instances
    // - One third are used for handling disk IO
    // - One third (in practice, less than) are used for handling all other
    //   computation/orchestration
    let threads = num_cpus::get() * 3;
    let mut rt = Builder::new()
        .threaded_scheduler()
        .core_threads(threads)
        .enable_io()
        .build()
        .context(CreateRuntime)?;

    // Arc-wrapped as they're referenced from within multiple Futures
    let config = Arc::new(config);
    let tmpdir = Arc::new(TempDir {
        path: PathBuf::from(&config.output).join(TMP_DIR_NAME),
    });
    rt.block_on(main_task(config, tmpdir).with_logger(log.new(o!("scope" => "main_task"))))?;
    Exit::Ok
}

async fn main_task(config: Arc<ReifiedConfig>, tmpdir: Arc<TempDir>) -> Result<(), Error> {
    let log = slog_scope::logger();
    // Ensure temporary directory exists and is empty
    ensure_tmpdir(tmpdir.as_ref()).await?;

    // 1. Create a job-queueing channel (a stream?)
    let (tx, rx) = mpsc::channel(QUEUE_BUFFER);

    // 2. Spawn a second task that is responsible for scanning the filesystem, queuing jobs, and
    //    eventually pushing the stream-end type
    info!(log, "Spawning filesytem scanner");
    let scanner = tokio::spawn(
        scan_source_files(config.clone(), tmpdir.clone(), tx)
            .with_logger(log.new(o!("scope" => "scan"))),
    );

    // 3. Spawn a task that consumes this stream using a buffer_unordered consumer, buffered to the
    //    # of hardware threads, and that quits when the stream pops an explicit end type
    info!(log, "Spawning library harmoniser");
    let harmoniser = tokio::spawn(
        harmonise_music(config, tmpdir, rx).with_logger(log.new(o!("scope" => "harmonise"))),
    );

    // 4. Block on completion of both tasks (`join!`?)
    info!(log, "Waiting for completion...");
    let (scanner, harmoniser) = try_join!(scanner, harmoniser).context(MainJoin)?;
    scanner?;
    harmoniser?;

    info!(log, "All done!");
    Ok(())
}

fn setup_logging(opt: &Opt) -> slog_scope::GlobalLoggerGuard {
    let log_level: slog::Level = opt.log_level.into();

    // Create logger
    let decorator = slog_term::PlainDecorator::new(std::io::stderr());
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = LevelFilter::new(drain, log_level).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!("scope" => "root"));
    debug!(
        &log,
        "Logging setup, command-line options received: {:?}", opt
    );

    // std::log interop
    let guard = slog_scope::set_global_logger(log);
    slog_stdlog::init().expect("Initialise slog/std::log interop");
    guard
}

fn build_config(opt: &Opt) -> Result<Config, Error> {
    let log = slog_scope::logger();
    // Config preferences order:
    // 1. Read config file passed at CLI
    // 2. Read config file from XDG directory
    // 3. Use defaults
    let mut config: Config = opt
        .config_file
        .clone()
        .map(|path| load_config(&path))
        .or_else(|| {
            dirs::config_dir().map(|path| {
                let path = path.join("harmonise").join("config.toml");
                load_config(&path)
            })
        })
        .unwrap_or_else(|| Ok(Config::default()))?;

    // Prefer source/output given at CLI to those in a configuration file
    config.source = opt.source.clone().or(config.source);
    config.output = opt.output.clone().or(config.output);

    debug!(log, "Configuration parsed and merged: {:?}", config);

    Ok(config)
}

fn load_config(path: &Path) -> Result<Config, Error> {
    let mut config_file_buf = vec![];
    std::fs::File::open(path)
        .context(ConfigFileOpen { path })?
        .read_to_end(&mut config_file_buf)
        .context(ConfigFileRead { path })?;
    Ok(toml::from_slice(&config_file_buf).context(ConfigParse { path })?)
}

async fn ensure_tmpdir<P>(tmpdir: P) -> Result<(), Error>
where
    P: AsRef<Path>,
{
    let log = slog_scope::logger();
    let tmpdir = tmpdir.as_ref();
    if tmpdir.async_exists().await.context(TmpDirExist {
        tmpdir: tmpdir.clone(),
    })? {
        warn!(
            log,
            "Found left-over temporary directory at `{}`, cleaning it up...",
            tmpdir.display()
        );
        fs::remove_dir_all(&tmpdir).await.context(TmpDirCleanup {
            tmpdir: tmpdir.clone(),
        })?;
    };
    fs::create_dir_all(&tmpdir)
        .await
        .context(TmpDirCreate { tmpdir })
}

async fn scan_source_files(
    config: Arc<ReifiedConfig>,
    tmpdir: Arc<TempDir>,
    harmonise_queue: mpsc::Sender<HarmoniseJob>,
) -> Result<(), Error> {
    // TODO can I use a bufferunordered instead of try_for_each_concurrent here...?
    let jobs = num_cpus::get();
    scan_tree(config, tmpdir, harmonise_queue)
        .try_for_each_concurrent(jobs, |_| async { Ok(()) })
        .await
}

fn scan_tree(
    config: Arc<ReifiedConfig>,
    tmpdir: Arc<TempDir>,
    harmonise_queue: mpsc::Sender<HarmoniseJob>,
) -> impl Stream<Item = Result<(), Error>> + Send + 'static {
    let log = slog_scope::logger();
    // Initialise the stack of directories to scan/compare, and unfold a stream of futures to
    // process the scan/compare jobs
    let (source_root, output_root) = (config.source.clone(), config.output.clone());
    stream::unfold(vec![(source_root, output_root)], move |mut to_visit| {
        let log = log.clone();
        let config = config.clone();
        let tmpdir = tmpdir.clone();
        let harmonise_queue = harmonise_queue.clone();
        async move {
            let (source, output) = to_visit.pop()?;
            let source_str = source.to_string_lossy().into_owned();
            let output_str = output.to_string_lossy().into_owned();
            let visit_res = scan_one(
                config,
                tmpdir,
                source,
                output,
                harmonise_queue,
                &mut to_visit,
            )
            .with_logger(log.new(o!(
                "source" => source_str,
                "output" => output_str
            )))
            .await;
            Some((visit_res, to_visit))
        }
    })
}

async fn scan_one(
    config: Arc<ReifiedConfig>,
    tmpdir: Arc<TempDir>,
    source: PathBuf,
    output: PathBuf,
    harmonise_queue: mpsc::Sender<HarmoniseJob>,
    to_visit: &mut Vec<ScanJob>,
) -> Result<(), Error> {
    let log = slog_scope::logger();
    info!(log, "Scanning and comparing source vs output",);

    // Scan both directories and get their files' metadata
    let (source_map, mut output_map) =
        try_join!(scan_map_for_dir(&source), scan_map_for_dir(&output))?;

    // Sanitise and filter source file names to match outputs against, determine type of harmonise
    // job per source
    let match_job_map = scan_map_to_match_job_map(config, source_map);

    // Dispatch harmonise jobs based on state of source and output files
    dispatch_harmonise_jobs(
        &output,
        harmonise_queue,
        match_job_map,
        to_visit,
        &mut output_map,
    )
    .await?;

    // Remove orphaned output files
    remove_orphaned_outputs(tmpdir, output_map).await
}

async fn scan_map_for_dir<P>(dir: P) -> Result<ScanMap, Error>
where
    P: AsRef<Path>,
{
    let entries = fs::read_dir(dir).await.context(ScanDir)?;
    entries
        .then(async move |res| {
            let entry = res.context(ScanDirEntry)?;
            Result::<(OsString, (PathBuf, Metadata)), Error>::Ok((
                entry.file_name(),
                (
                    entry.path().into(),
                    entry.metadata().await.context(ScanDirMetadata)?,
                ),
            ))
        })
        .try_collect()
        .await
}

fn scan_map_to_match_job_map(config: Arc<ReifiedConfig>, scan_map: ScanMap) -> MatchJobMap {
    scan_map
        .into_iter()
        .map(|(name, (path, metadata))| {
            // Extract extension if file
            match metadata.is_file() {
                true => {
                    let extension = path.extension().map(|ext| ext.to_os_string());
                    (name, (path, metadata, extension))
                }
                false => (name, (path, metadata, None)),
            }
        })
        .filter(|(_name, (_path, metadata, extension))| {
            // Filter so we have directories, and files with valid music extensions
            (metadata.is_dir()
                || match extension {
                    None => false,
                    Some(extension) => config.music_filetypes.contains(extension.as_os_str()),
                })
        })
        .map(|(_name, (path, metadata, extension))| {
            // Determine output names to match against, and job type for files
            let name_path = sanitise_name(config.clone(), &path);
            if metadata.is_file() {
                let ext = extension.expect("Unwrap an extension we know is present");
                let (ext, job_type) = if config.lossy_filetypes.contains(ext.as_os_str()) {
                    (ext, HarmoniseJobType::Copy)
                } else {
                    (OsString::from("ogg"), HarmoniseJobType::Transcode)
                };
                let name = name_path
                    .with_extension(ext)
                    .file_name()
                    .expect("Unwrap a filename we know is present")
                    .to_os_string();
                (name, (path, metadata, Some(job_type)))
            } else {
                let name = name_path
                    .file_name()
                    .expect("Unwrap a filename we know is present")
                    .to_os_string();
                (name, (path, metadata, None))
            }
        })
        .collect()
}

fn sanitise_name(config: Arc<ReifiedConfig>, source_path: &Path) -> PathBuf {
    let source_name = source_path
        .file_name()
        .expect("Get filename for known-valid path");
    // Replace unsafe characters with surrogates
    // TODO during scanning perform collision detection on the sanitised names?
    let sanitised_name = config
        .replace_pattern
        .replace_all(source_name.as_bytes(), "_".as_bytes());
    source_path.with_file_name(OsStr::from_bytes(sanitised_name.as_ref()))
}

async fn dispatch_harmonise_jobs(
    output: &Path,
    mut harmonise_queue: mpsc::Sender<HarmoniseJob>,
    match_job_map: MatchJobMap,
    to_visit: &mut Vec<ScanJob>,
    output_map: &mut ScanMap,
) -> Result<(), Error> {
    let log = slog_scope::logger();
    for (match_name, (source_path, source_metadata, job_type)) in match_job_map {
        debug!(log, "Checking source path {}", source_path.display());
        let out_path = &output.join(&match_name);
        if source_metadata.is_file() {
            // We use HashMap::remove() here, meaning any remaining output entries after this for
            // loop are orphans, and can be killed
            let harmonise = match output_map.remove(&match_name) {
                // If the path wasn't in the map, then the output does not exist and we must
                // harmonise it
                None => true,
                Some((out_path, out_metadata)) => {
                    if !out_metadata.is_file() {
                        info!(
                            log,
                            "Removing unexpected output directory `{}`",
                            out_path.display()
                        );
                        fs::remove_dir_all(&out_path)
                            .await
                            .context(ScanUnexpectedPath {
                                path: out_path,
                                path_type: "directory",
                            })?;
                        true
                    } else {
                        // Otherwise, compare the modified times
                        let out_time =
                            out_metadata
                                .modified()
                                .context(ScanOutputFileModifiedTime {
                                    path: out_path.clone(),
                                })?;
                        let source_time =
                            source_metadata
                                .modified()
                                .context(ScanSourceFileModifiedTime {
                                    path: source_path.clone(),
                                })?;
                        source_time > out_time
                    }
                }
            };
            if harmonise {
                debug!(
                    log,
                    "Queueing harmonise job for  path pair:\n\t{}\n\t{}",
                    source_path.display(),
                    out_path.display()
                );
                let job = HarmoniseJob {
                    source: source_path.clone(),
                    output: out_path.clone(),
                    job_type: job_type.expect("Unwrap a job type for a file to harmonise"),
                };
                harmonise_queue
                    .send(job)
                    .await
                    .context(HarmoniseQueuePush)?;
            };
        } else {
            if let Some((out_path, out_metadata)) = output_map.remove(&match_name) {
                debug!(log, "Output path exists: {}", out_path.display());
                if !out_metadata.is_dir() {
                    info!(
                        log,
                        "Removing unexpected output file `{}`",
                        out_path.display()
                    );
                    fs::remove_file(&out_path)
                        .await
                        .context(ScanUnexpectedPath {
                            path: out_path,
                            path_type: "file",
                        })?;
                };
            } else {
                debug!(
                    log,
                    "Output path does not exist, creating directory: {}",
                    out_path.display()
                );
                fs::create_dir_all(&out_path)
                    .await
                    .context(ScanOutputDirCreate {
                        path: out_path.clone(),
                    })?;
            };
            // Add to the stack of directories to scan
            to_visit.push((source_path.clone(), out_path.clone()));
        };
    }
    Ok(())
}

async fn remove_orphaned_outputs(
    tmpdir: Arc<TempDir>,
    remaining_output_map: ScanMap,
) -> Result<(), Error> {
    let log = slog_scope::logger();
    for (_name, (out_path, out_metadata)) in &remaining_output_map {
        if out_path == (*tmpdir).as_ref() {
            // Don't touch the tmpdir :o
            continue;
        }
        if out_metadata.is_file() {
            info!(log, "Removing orphaned output file {}", out_path.display());
            fs::remove_file(&out_path).await.context(ScanOrphanPath {
                path: out_path,
                path_type: "file",
            })?;
        } else {
            info!(
                log,
                "Removing orphaned output directory {}",
                out_path.display()
            );
            fs::remove_dir_all(&out_path)
                .await
                .context(ScanOrphanPath {
                    path: out_path,
                    path_type: "directory",
                })?;
        }
    }
    Ok(())
}

async fn harmonise_music(
    config: Arc<ReifiedConfig>,
    tmpdir: Arc<TempDir>,
    queue: mpsc::Receiver<HarmoniseJob>,
) -> Result<(), Error> {
    let log = slog_scope::logger();
    let jobs = num_cpus::get();
    queue
        .then(async move |job| Result::<HarmoniseJob, Error>::Ok(job))
        .try_for_each_concurrent(jobs, |job| {
            harmonise(config.clone(), tmpdir.clone(), job).with_logger(log.clone())
        })
        .await
}

async fn harmonise(
    config: Arc<ReifiedConfig>,
    tmpdir: Arc<TempDir>,
    job: HarmoniseJob,
) -> Result<(), Error> {
    let log = slog_scope::logger();
    debug!(log, "Got harmonise job: {:?}", job);

    // Get path for a temporary output file
    let tmp_path = temp_file_path(tmpdir).await?;

    match &job.job_type {
        HarmoniseJobType::Transcode => {
            debug!(
                log,
                "Transcoding `{}` -> `{}`",
                job.source.display(),
                tmp_path.display()
            );
            // Run ffmpeg to produce the output file
            // TODO detect whether ffmpeg binary is present before attempting to use it, error out
            // if it is not -- should just be done once at startup really
            // TODO detect whether nice binary is present before attempting to use it, warn if not
            // TODO nice via syscall instead?
            let mut cmd = Command::new("nice");
            if config.nice.enable {
                cmd.args(&[&format!("-n{}", config.nice.level), "--"]);
            };
            let proc = cmd
                .arg("ffmpeg")
                .args(&["-v", "quiet", "-y", "-i"])
                .arg(&job.source)
                .args(&[
                    "-codec:a",
                    "libvorbis",
                    "-qscale:a",
                    "8",
                    "-map_metadata",
                    "0",
                    "-f",
                    "ogg",
                ])
                .arg(&tmp_path)
                .spawn()
                .context(HarmoniseFfmpegSpawn)?;
            let status = proc.await.context(HarmoniseFfmpegWait)?;
            if !status.success() {
                return Err(Error::FfmpegFailed { status, job });
            } else {
                debug!(log, "Transcoded to temporary file {}", tmp_path.display());
            };
        }
        HarmoniseJobType::Copy => {
            debug!(
                log,
                "Copying `{}` -> `{}`",
                job.source.display(),
                tmp_path.display()
            );
            fs::copy(&job.source, &tmp_path)
                .await
                .context(HarmoniseCopy {
                    from: job.source,
                    to: tmp_path.clone(),
                })?;
        }
    };

    // Move the output file from the temp path to the final path
    fs::rename(&tmp_path, &job.output)
        .await
        .context(HarmoniseTmpMove {
            from: tmp_path,
            to: job.output.clone(),
        })?;

    info!(log, "Harmonised output file {}", job.output.display());
    Ok(())
}

// Ensures the temporary file is unique by retrying up to TMP_FILE_RETRIES times on create_new()
// failure
async fn temp_file_path(tmpdir: Arc<TempDir>) -> Result<PathBuf, Error> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    for _ in 0..TMP_FILE_RETRIES {
        let random_string: String = thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .collect();
        let path = (*tmpdir).as_ref().join(random_string);
        match opts.open(&path).await {
            Err(e) => {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    continue;
                } else {
                    return Err(Error::HarmoniseTmpCreate { path, source: e });
                }
            }
            Ok(_) => return Ok(path),
        };
    }

    Err(Error::HarmoniseTmpCreateRetries)
}

#[derive(Debug)]
struct HarmoniseJob {
    source: PathBuf,
    output: PathBuf,
    job_type: HarmoniseJobType,
}

#[derive(Debug)]
enum HarmoniseJobType {
    Copy,
    Transcode,
}

type ScanJob = (PathBuf, PathBuf);
type ScanMap = HashMap<OsString, (PathBuf, Metadata)>;
type MatchJobMap = HashMap<OsString, (PathBuf, Metadata, Option<HarmoniseJobType>)>;

// Helpers {{{
#[async_trait]
trait AsyncPath {
    async fn async_exists(&self) -> Result<bool, io::Error>;
    async fn async_metadata(&self) -> Result<Metadata, io::Error>;
}
#[async_trait]
impl AsyncPath for Path {
    async fn async_exists(&self) -> Result<bool, io::Error> {
        fs::symlink_metadata(self).await.map_or_else(
            |err| match err.kind() {
                io::ErrorKind::NotFound => Ok(false),
                _ => Err(err),
            },
            |_metadata| Ok(true),
        )
    }
    async fn async_metadata(&self) -> Result<Metadata, io::Error> {
        fs::symlink_metadata(self).await
    }
}

// Minimal self-cleaning temporary directory
struct TempDir {
    path: PathBuf,
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        self.path.as_ref()
    }
}

// Essentially ionices ourself
// TODO move this to its own tiny crate, along with non-io nicing?
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))] // safe u32 -> usize cast
fn lower_own_io_priority(config: &ReifiedConfig) -> Result<(), Error> {
    let pid = std::process::id();
    let prio = (&config.ionice.level).into();
    // TODO handle error values? Probably not much point.
    raw_ioprio_set(IOPRIO_WHO_PROCESS, pid as usize, prio);
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum IoPrioValue {
    #[serde(deserialize_with = "ioprio_level_in_range")]
    RealTime(usize),
    #[serde(deserialize_with = "ioprio_level_in_range")]
    BestEffort(usize),
    Idle,
}

fn ioprio_level_in_range<'de, D>(d: D) -> Result<usize, D::Error>
where
    D: de::Deserializer<'de>,
{
    let val: usize = Deserialize::deserialize(d)?;

    if val < IOPRIO_LEVEL_NR {
        Err(de::Error::invalid_value(
            de::Unexpected::Unsigned(val as u64),
            &"a number between 0 and 7, inclusive",
        ))
    } else {
        Ok(val)
    }
}

impl From<&IoPrioValue> for usize {
    fn from(val: &IoPrioValue) -> Self {
        match val {
            IoPrioValue::RealTime(level) => ioprio_prio_value(IOPRIO_CLASS_RT, *level),
            IoPrioValue::BestEffort(level) => ioprio_prio_value(IOPRIO_CLASS_BE, *level),
            IoPrioValue::Idle => ioprio_prio_value(IOPRIO_CLASS_IDLE, 0),
        }
    }
}
#[inline]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn ioprio_prio_value(class: i32, data: usize) -> usize {
    ((class as usize) << IOPRIO_CLASS_SHIFT) | data
}

// fn foprio_realtime_vvalidation<'de, D>(d: D) -> Result<IoPrioValue>
const IOPRIO_LEVEL_NR: usize = 8;

const IOPRIO_CLASS_SHIFT: u8 = 13;
const IOPRIO_CLASS_RT: i32 = 1;
const IOPRIO_CLASS_BE: i32 = 2;
const IOPRIO_CLASS_IDLE: i32 = 3;

const IOPRIO_WHO_PROCESS: i32 = 1;
// const IOPRIO_WHO_PGRP: i32 = 2;
// const IOPRIO_WHO_USER: i32 = 3;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn raw_ioprio_set(which: i32, who: usize, prio: usize) -> usize {
    unsafe {
        // NOTE: I'm pretty sure that if this syscall is actually unsafe, that'd mean we have a
        // kernel bug...
        syscall!(IOPRIO_SET, which, who, prio) as usize
    }
}
// }}}

// Error type and related {{{
#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Failed to open configuration file `{}`: {}", path.display(), source))]
    ConfigFileOpen {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to read configuration file `{}`: {}", path.display(), source))]
    ConfigFileRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Failed to parse configuration file as TOML `{}`: {}", path.display(), source))]
    ConfigParse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[snafu(display("No 'source' directory specified via CLI or configuration file"))]
    ConfigNoSource,
    #[snafu(display("No 'output' directory specified via CLI or configuration file"))]
    ConfigNoOutput,
    #[snafu(display("Failed to create Tokio runtime: {}", source))]
    CreateRuntime {
        source: tokio::io::Error,
    },
    #[snafu(display("Failed to join main tasks: {}", source))]
    MainJoin {
        source: task::JoinError,
    },
    #[snafu(display("Failed to scanner task: {}", source))]
    ScannerJoin {
        source: task::JoinError,
    },
    #[snafu(display("Failed to check existence of temporary directory `{}`: {}", tmpdir.display(), source))]
    TmpDirExist {
        tmpdir: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Failed to create temporary directory `{}`: {}", tmpdir.display(), source))]
    TmpDirCreate {
        tmpdir: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Failed to remove temporary directory `{}` for cleanup: {}", tmpdir.display(), source))]
    TmpDirCleanup {
        tmpdir: PathBuf,
        source: io::Error,
    },
    #[snafu(display("One or more scan workers failed: {}", errors))]
    Scan {
        errors: ErrorList,
    },
    #[snafu(display("Error scanning directory: {}", source))]
    ScanDir {
        source: io::Error,
    },
    #[snafu(display("Error reading directory entry during scan: {}", source))]
    ScanDirEntry {
        source: io::Error,
    },
    #[snafu(display("Error reading directory entry's metadata during scan: {}", source))]
    ScanDirMetadata {
        source: io::Error,
    },
    #[snafu(display("Failed to join directory map scan task: {}", source))]
    ScanDirMapJoin {
        source: task::JoinError,
    },
    #[snafu(display("Failed to remove orphaned {} `{}`: {}", path_type, path.display(), source))]
    ScanOrphanPath {
        path: PathBuf,
        path_type: String,
        source: io::Error,
    },
    #[snafu(display("Failed to remove unexpected {} `{}` in output: {}", path_type, path.display(), source))]
    ScanUnexpectedPath {
        path: PathBuf,
        path_type: String,
        source: io::Error,
    },
    #[snafu(display("Failed to create output directory `{}` in output: {}", path.display(), source))]
    ScanOutputDirCreate {
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Error reading output file `{}`'s last-modified time during scan: {}", path.display(), source))]
    ScanOutputFileModifiedTime {
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Failed to check existence of output path `{}`: {}", path.display(), source))]
    ScanOutputPathExist {
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Error reading source file `{}`'s last-modified time during scan: {}", path.display(), source))]
    ScanSourceFileModifiedTime {
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Failed to queue up new harmonise job: {:?}", source))]
    HarmoniseQueuePush {
        source: mpsc::error::SendError<HarmoniseJob>,
    },
    #[snafu(display("Failed to spawn ffmpeg subprocess: {:?}", source))]
    HarmoniseFfmpegSpawn {
        source: tokio::io::Error,
    },
    #[snafu(display("Failure while awaiting ffmpeg subprocess: {:?}", source))]
    HarmoniseFfmpegWait {
        source: tokio::io::Error,
    },
    #[snafu(display("ffmpeg exited with non-zero status '{}' for job {:?}", status, job))]
    FfmpegFailed {
        status: std::process::ExitStatus,
        job: HarmoniseJob,
    },
    #[snafu(display("Failed to copy file for harmonise job:\n\t\tFrom: {}\n\t\tTo: {}\n\t{}", from.display(), to.display(), source))]
    HarmoniseCopy {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[snafu(display("Failed to move temporary file for harmonise job:\n\t\tFrom: {}\n\t\tTo: {}\n\t{}", from.display(), to.display(), source))]
    HarmoniseTmpMove {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[snafu(display(
        "Failed to create temporary file `{}` for harmonise job: {}",
        path.display(),
        source
    ))]
    HarmoniseTmpCreate {
        path: PathBuf,
        source: io::Error,
    },
    #[snafu(display(
        "Failed to create temporary file for harmonise job #{} retries failed",
        TMP_FILE_RETRIES,
    ))]
    HarmoniseTmpCreateRetries,
    Placeholder,
}

#[derive(Debug)]
struct ErrorList(pub Vec<Error>);

impl std::fmt::Display for ErrorList {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut first = true;
        write!(f, "[ ")?;
        for err in self.0.iter() {
            write!(f, "{}", err)?;
            if !first {
                write!(f, ", ")?;
            } else {
                first = false;
            }
        }
        write!(f, " ]")?;
        Ok(())
    }
}
// }}}

// Error -> Status code mappings {{{
impl From<Error> for i32 {
    fn from(err: Error) -> Self {
        match err {
            _ => exit_code::FAILURE,
        }
    }
}
impl ExitDisplay for Error {
    fn display(&self) -> String {
        // TODO Better error message here? Print embedded backtraces?
        format!("{}", self)
    }
}
// }}}
