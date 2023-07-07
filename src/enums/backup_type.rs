use clap::ValueEnum;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum BackupType {
    NewToken,
    FreeOtp,
    GoogleAuth,
}
