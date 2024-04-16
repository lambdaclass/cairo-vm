use thiserror_no_std::Error;

#[derive(Eq, Hash, PartialEq, Debug, Error)]
pub enum CairoPieValidationError {
    #[error("Invalid main() address.")]
    InvalidMainAddress,
    #[error("Program length does not match the program segment size.")]
    ProgramLenVsSegmentSizeMismatch,
    #[error("Builtin list mismatch in builtin_segments.")]
    BuiltinListVsSegmentsMismatch,
    #[error("Invalid segment size for ret_fp. Must be 0.")]
    InvalidRetFpSegmentSize,
    #[error("Invalid segment size for ret_pc. Must be 0.")]
    InvalidRetPcSegmentSize,
    #[error("Invalid segment index for program_segment.")]
    InvalidProgramSegmentIndex,
    #[error("Invalid segment index for execution_segment.")]
    InvalidExecutionSegmentIndex,
    #[error("Invalid segment index for {0}.")]
    InvalidBuiltinSegmentIndex(&'static str),
    #[error("Invalid segment index for ret_fp_segment.")]
    InvalidRetFpSegmentIndex,
    #[error("Invalid segment index for ret_pc_segment.")]
    InvalidRetPcSegmentIndex,
    #[error("Invalid segment indices for extra_segments.")]
    InvalidExtraSegmentIndex
}
