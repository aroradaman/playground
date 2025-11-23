package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

const (
	// goRoutines is the number of goroutines for resolving DNS queries.
	goRoutines = 100

	// interval in millisecond between each dns resolution request.
	interval = 1000
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

// query queries the DNS server for random domain name lookup, sleeps for the given interval
// after every resolution.
func query() {
	var domain string
	for {
		domain = fmt.Sprintf("%s.com", RandStringRunes(5+rand.Intn(100)))
		ips, err := net.LookupIP(domain)
		fmt.Println(domain, ips, err)

		time.Sleep(time.Duration(interval) * time.Millisecond)
	}
}

func main() {
	wg := sync.WaitGroup{}

	for i := 0; i < goRoutines; i++ {
		wg.Add(1)
		go query()
	}

	wg.Wait()
}
