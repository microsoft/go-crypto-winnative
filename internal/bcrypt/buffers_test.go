// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package bcrypt

import (
	"math"
	"strconv"
	"testing"
)

func TestCheckBufferSizes(t *testing.T) {
	type testCase struct {
		name  string
		sizes []int
		valid bool
	}
	tests := []testCase{
		{"empty", nil, true},
		{"zero", []int{0}, true},
		{"small", []int{1, 16, 32}, true},
		{"max-int32", []int{math.MaxInt32}, true},
		{"negative", []int{16, -1, 32}, false},
	}
	if strconv.IntSize == 64 {
		limit := uint64(1) << 32
		tests = append(tests,
			testCase{"max-uint32", []int{int(limit - 1)}, true},
			testCase{"overflow", []int{16, int(limit), 32}, false},
			testCase{"overflow-with-prefix", []int{int(limit + 1)}, false},
		)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckBufferSizes(tt.sizes...)
			if (err == nil) != tt.valid {
				t.Fatalf("CheckBufferSizes(%v) = %v, valid: %v", tt.sizes, err, tt.valid)
			}
			if err != nil && err != errBufferTooLarge {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheckBufferSizesAllocations(t *testing.T) {
	if n := testing.AllocsPerRun(100, func() {
		if err := CheckBufferSizes(0, 16, 32, math.MaxInt32); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatalf("allocations = %v, want 0", n)
	}
}
