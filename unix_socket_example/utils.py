from array import array
from typing import Union
import json

class RelocatableValue:
    """
    A value in the cairo vm representing an address in some memory segment. This is meant to be
    replaced by a real memory address (field element) after the VM finished.
    """
    segment_index: int
    offset: int

    def __init__(self, j):
        self.__dict__ = json.loads(j)

MaybeRelocatable = Union[int, RelocatableValue]

class Memory:
    data: array

    def __init__(self, j):
        self.__dict__ = json.loads(j)
