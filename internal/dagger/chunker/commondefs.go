package dgrchunker

import (
	"github.com/ribasushi/fil-discover-check/chunker"
	"github.com/ribasushi/fil-discover-check/internal/constants"
)

type InstanceConstants struct {
	_            constants.Incomparabe
	MinChunkSize int
	MaxChunkSize int
}

type DaggerConfig struct {
	IsLastInChain bool
}

type Initializer func(
	chunkerCLISubArgs []string,
	cfg *DaggerConfig,
) (
	instance chunker.Chunker,
	constants InstanceConstants,
	initErrorStrings []string,
)
