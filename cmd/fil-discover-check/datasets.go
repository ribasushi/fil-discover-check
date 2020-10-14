package main

import (
	"encoding/binary"
	"log"

	rice "github.com/GeertJohan/go.rice"
)

const knownCarCount = 4159209

var dataSets = map[uint8]string{
	10: "dumbo-stage3-datasets.elasticmapreduce",
	27: "dumbo-stage3-fast-ai-nlp",
	29: "dumbo-stage3-gdelt-open-data",
	16: "dumbo-stage3-source-berkeley",
	18: "dumbo-stage3-source-fma",
	23: "dumbo-stage3-source-gnomadv3",
	15: "dumbo-stage3-source-wikipedia",
	2:  "dumbo-v2-cars-1000genomes",
	11: "dumbo-v2-cars-allencell",
	17: "dumbo-v2-cars-datasets.elasticmapreduce",
	6:  "dumbo-v2-cars-dumbo-internet-archive-librivox",
	5:  "dumbo-v2-cars-dumbo-internet-archive-prelinger",
	1:  "dumbo-v2-cars-encode-public",
	28: "dumbo-v2-cars-fast-ai-nlp",
	12: "dumbo-v2-cars-gdelt-open-data",
	13: "dumbo-v2-cars-google-landmark",
	3:  "dumbo-v2-cars-landsat-pds",
	9:  "dumbo-v2-cars-mevadata-public-01",
	21: "dumbo-v2-cars-openaq-fetches",
	8:  "dumbo-v2-cars-openneuro.org",
	4:  "dumbo-v2-cars-prd-tnm",
	7:  "dumbo-v2-cars-source-berkeley",
	20: "dumbo-v2-cars-source-fma",
	19: "dumbo-v2-cars-source-gnomadv3",
	14: "dumbo-v2-cars-source-gutenberg",
	26: "dumbo-v2-cars-source-offshore",
	25: "dumbo-v2-cars-source-openaddresses",
	24: "dumbo-v2-cars-source-openstreetmaps",
	22: "dumbo-v2-cars-source-wikipedia",
}

type carData struct {
	datasetID    uint8
	expectedSize uint32
	commP        [16]byte
}

var knownCars = make(map[[16]byte]carData, knownCarCount)

func loadDatasetDescriptions() {

	var DataBox = rice.MustFindBox("../../tmp/data/")

	d, err := DataBox.Bytes("fil_discover_full.dat")
	if err != nil {
		log.Fatalf("unable to read list of known dumbo cars: %s", err)
	}

	var i int
	var key, commP [16]byte
	for i < len(d) {
		copy(key[:], d[i:i+16])
		copy(commP[:], d[i+21:i+37])
		knownCars[key] = carData{
			datasetID:    d[i+16],
			expectedSize: binary.BigEndian.Uint32(d[i+17 : i+21]),
			commP:        commP,
		}
		i += 37
	}
}
