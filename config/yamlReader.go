package config

import (
	"io/ioutil"
	"log"

	"gopkg.in/yaml.v3"
)

// YamlReader This reads the yaml config file
type YamlReader struct {
	filePath string
}

// NewYamlReader Constructs a YamlReader from a file path
func NewYamlReader(filePath string) *YamlReader {
	return &YamlReader{filePath: filePath}
}

// GetPeerConfig Return the config read from the yaml file
func (rdr *YamlReader) GetPeerConfig() *PeerConfig {
	// The error handling should be different
	data, err := ioutil.ReadFile(rdr.filePath)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	config := PeerConfig{}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	return &config
}
