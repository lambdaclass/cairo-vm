from starkware.cairo.common.segments import relocate_segment
from starkware.cairo.common.alloc import alloc

func main() {
    // Create a new segment
    let (segment: felt*) = alloc();

    // Insert a value into the segment beyond the end of the segment.
    assert segment[0] = cast(segment, felt) + 100;

    return ();
}
