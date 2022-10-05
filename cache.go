package main

import (
	"encoding/json"
	"fmt"
	"github.com/allegro/bigcache/v3"
	"net"
	"os"
	"time"
)

func NewCache() *bigcache.BigCache {
	cache, err := bigcache.NewBigCache(bigcache.DefaultConfig(5 * time.Minute))
	if err != nil {
		fmt.Println("failed to spin up cache. Exiting...")
		os.Exit(-1)
	}
	return cache
}

func NetNStoCacheValueBytes(ns []*net.NS) []byte {
	data, err := json.Marshal(ns)
	if err != nil {
		return []byte{}
	}
	return data
}

func NetNSBytestoNetNS(data []byte) []*net.NS {
	var ns []*net.NS
	_ = json.Unmarshal(data, &ns)
	return ns
}
