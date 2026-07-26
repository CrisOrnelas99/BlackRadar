package main

import (
	"context"
	"log"

	"blackradar/api/platform/runtime"
)

func main() {
	if err := runtime.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
