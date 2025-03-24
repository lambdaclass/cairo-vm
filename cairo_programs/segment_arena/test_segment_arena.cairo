// This test contains parts imported from cairo-lang
// https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/starknet/builtins/segment_arena/segment_arena_test.cairo

from starkware.cairo.common.alloc import alloc

// Represents the information about a single segment allocated by the arena.
struct SegmentInfo {
    // A pointer to the first element of this segment.
    start: felt*,
    // A pointer to the end of this segment (the first unused element).
    end: felt*,
    // A sequential id, assigned to the segment when it is finalized.
    // This value is used to guarantee that 'end' is not assigned twice.
    finalization_index: felt,
}

// Represents the status of the segment arena.
struct SegmentArenaBuiltin {
    // A pointer to a list of SegmentInfo. infos[i] contains information about the i-th segment
    // (ordered by construction).
    // The value is fixed during the execution of an entry point.
    infos: SegmentInfo*,
    // The number of segments that were created so far.
    n_segments: felt,
    // The number of segments that were finalized so far.
    n_finalized: felt,
}

// Constructs a new segment for the segment arena builtin and initializes it with an empty instance
// of `SegmentArenaBuiltin`.
func new_arena() -> SegmentArenaBuiltin* {
    let (segment_arena: SegmentArenaBuiltin*) = alloc();
    assert segment_arena[0] = SegmentArenaBuiltin(
        infos=cast(nondet %{ segments.add() %}, SegmentInfo*), n_segments=0, n_finalized=0
    );
    return &segment_arena[1];
}

// Validates the segment arena builtin.
//
// In particular, relocates the temporary segments such that the start of segment i is strictly
// larger than the end of segment i+1.
func validate_segment_arena(segment_arena: SegmentArenaBuiltin*) {
    tempvar n_segments = segment_arena.n_segments;
    tempvar n_finalized = segment_arena.n_finalized;
    // The following line should follow from the fact that every allocated segment
    // must be finalized exactly once.
    // We keep it both as a sanity check and since Sierra compilation is not proven yet.
    assert n_segments = n_finalized;

    if (n_segments == 0) {
        return ();
    }

    // The following call also implies that n_segments > 0.
    _verify_continuity(infos=segment_arena.infos, n_segments_minus_one=n_segments - 1);
    return ();
}

// Helper function for validate_segment_arena.
func _verify_continuity(infos: SegmentInfo*, n_segments_minus_one: felt) {
    if (n_segments_minus_one == 0) {
        // If there is only one segment left, there is no need to check anything.
        return ();
    }

    // Enforce an empty cell between two consecutive segments so that the start of a segment
    // is strictly bigger than the end of the previous segment.
    // This is required for proving the soundness of this construction, in the case where a segment
    // has length zero.

    // Note: the following code was copied from relocate_segment() for efficiency reasons.
    let src_ptr = infos[1].start;
    let dest_ptr = infos[0].end + 1;
    %{ memory.add_relocation_rule(src_ptr=ids.src_ptr, dest_ptr=ids.dest_ptr) %}
    assert src_ptr = dest_ptr;

    return _verify_continuity(infos=&infos[1], n_segments_minus_one=n_segments_minus_one - 1);
}


// Creates a new segment using the segment arena.
func new_segment{segment_arena: SegmentArenaBuiltin*}() -> felt* {
    let prev_segment_arena = &segment_arena[-1];
    tempvar n_segments = prev_segment_arena.n_segments;
    tempvar infos = prev_segment_arena.infos;

    %{
        if 'segment_index_to_arena_index' not in globals():
            # A map from the relocatable value segment index to the index in the arena.
            segment_index_to_arena_index = {}

        # The segment is placed at the end of the arena.
        index = ids.n_segments

        # Create a segment or a temporary segment.
        start = segments.add_temp_segment() if index > 0 else segments.add()

        # Update 'SegmentInfo::start' and 'segment_index_to_arena_index'.
        ids.prev_segment_arena.infos[index].start = start
        segment_index_to_arena_index[start.segment_index] = index
    %}
    assert segment_arena[0] = SegmentArenaBuiltin(
        infos=infos, n_segments=n_segments + 1, n_finalized=prev_segment_arena.n_finalized
    );
    let segment_arena = &segment_arena[1];
    return infos[n_segments].start;
}

// Finalizes a given segment and returns the corresponding start.
func finalize_segment{segment_arena: SegmentArenaBuiltin*}(segment_end: felt*) -> felt* {
    let prev_segment_arena = &segment_arena[-1];
    tempvar n_segments = prev_segment_arena.n_segments;
    tempvar n_finalized = prev_segment_arena.n_finalized;

    // Guess the index of the segment.
    tempvar index = nondet %{ segment_index_to_arena_index[ids.segment_end.segment_index] %};

    // Write segment_end in the manager.
    tempvar infos: SegmentInfo* = prev_segment_arena.infos;
    tempvar segment_info: SegmentInfo* = &infos[index];
    // Writing n_finalized to 'finalization_index' guarantees 'segment_info.end' was not assigned
    // a value before.
    assert segment_info.finalization_index = n_finalized;
    assert segment_info.end = segment_end;

    assert segment_arena[0] = SegmentArenaBuiltin(
        infos=infos, n_segments=n_segments, n_finalized=n_finalized + 1
    );

    let segment_arena = &segment_arena[1];
    return segment_info.start;
}

func test_segment_arena() -> (felt*, SegmentInfo*) {
    alloc_locals;

    local segment_arena_start: SegmentArenaBuiltin* = new_arena();
    let segment_arena = segment_arena_start;

    with segment_arena {
        let segment0 = new_segment();
        let segment1 = new_segment();
        let segment2 = new_segment();

        assert segment0[0] = 1;
        assert segment0[1] = 2;

        assert segment1[0] = 3;
        assert segment1[1] = 4;

        assert segment2[0] = 5;

        assert finalize_segment(segment0 + 2) = segment0;
        assert finalize_segment(segment1 + 2) = segment1;

        let segment3 = new_segment();

        assert segment3[0] = 6;
        assert segment3[1] = 7;

        assert finalize_segment(segment3 + 2) = segment3;
        assert finalize_segment(segment2 + 1) = segment2;
    }
    validate_segment_arena(segment_arena=&segment_arena[-1]);
    return (segment0, segment_arena_start[-1].infos);
}

func main{}() {
    let (_segment0, _infos) = test_segment_arena();
    ret;
}
