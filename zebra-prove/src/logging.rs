use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::error::Error;

/// Configures and initializes the logger.
/// Returns a Result so main() can handle failure gracefully.
pub fn setup(level: LevelFilter) -> Result<(), Box<dyn Error>> {
    // 1. Console Appender
    // Pattern breakdown:
    // \x1b[90m{d(...)}\x1b[0m : Grey timestamp
    // {h({l})}               : Highlighted (colored) log level
    // {c}                    : The Category (Module path)
    // {m}                    : The Message
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "\x1b[90m{d(%Y-%m-%d %H:%M:%S)}\x1b[0m {h({l})} {t} - {m}\n",
        )))
        .build();

    // 2. Rolling File Appender Setup

    // A. Trigger: Rotate when file reaches 10MB
    let trigger = SizeTrigger::new(10 * 1024 * 1024);

    // B. Roller: Keep 5 archived files (app.1.log ... app.5.log)
    let roller = FixedWindowRoller::builder().build("log/app.{}.log", 5)?;

    // C. Policy: Combine Trigger + Roller
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

    // D. Create the file appender
    // Note: No ANSI colors (\x1b) here, just plain text structure.
    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} [{l}] {t} - {m}\n",
        )))
        .build("log/app.log", Box::new(policy))?;

    // 3. Compose the Config
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            Root::builder()
                .appender("stdout")
                .appender("logfile")
                .build(level),
        )?;

    // 4. Initialize the global logger
    log4rs::init_config(config)?;

    Ok(())
}
