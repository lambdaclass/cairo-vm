use std::{path::PathBuf, ptr::write};

use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_and, feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, NewHashFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{BacktraceObserver, StdMapObserver, TimeObserver},
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

use core::time::Duration;
use cairo_vm::cairo_run::cairo_run;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::hint_processor::builtin_hint_processor::builtin_hint_processor_definition::BuiltinHintProcessor;

/// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];
static mut SIGNALS_PTR: *mut u8 = unsafe { SIGNALS.as_mut_ptr() };

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

#[allow(clippy::similar_names)]
pub fn main() {
    // The closure that we want to fuzz
    let mut harness = |input: &BytesInput| {
        let cairo_config = CairoRunConfig::default();
        let mut hint_processor = BuiltinHintProcessor::new_empty();
        let target = input.target_bytes();
        let buf = target.as_slice();
        signals_set(0);

        if !buf.is_empty() {
            signals_set(1);
            if cairo_run(buf, &cairo_config, &mut hint_processor).is_ok() {
                signals_set(2);
            }
        }
        ExitKind::Ok
    };

    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", SIGNALS_PTR, SIGNALS.len()) };
    // Create a stacktrace observer to add the observers tuple
    let mut bt = None;
    let bt_observer = BacktraceObserver::new(
        "BacktraceObserver",
        &mut bt,
        libafl::observers::HarnessType::InProcess,
    );

    let time_observer = TimeObserver::new("time");
    //let feedback_state = 
    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
    let mut feedback = feedback_or!(MaxMapFeedback::new(&observer), TimeFeedback::with_observer(&time_observer));
    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or!(feedback_and!(CrashFeedback::new(), NewHashFeedback::new(&bt_observer)), TimeoutFeedback::new());

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the executor for an in-process function with just one observer
    let mut executor = TimeoutExecutor::new(
        InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer, bt_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        ).expect("Failed to create the Executor"),
        Duration::new(60, 0)
    );

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
