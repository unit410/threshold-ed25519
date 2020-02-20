package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReverse(test *testing.T) {
	reversed := Reverse([]byte{0x01, 0x02, 0x03})
	require.Equal(test, []byte{0x03, 0x02, 0x01}, reversed)
}
