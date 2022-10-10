package main

func ScanWorker(id int, jobs <-chan Query, results chan<- Result) {
	cache := NewCache()
	for j := range jobs {
		res := ProcessQuery([]Query{j}, cache,false)
		// Send and receive one query response, always look for response.
		results <- res[0]
	}
}
