package main

import (
	"fmt"
	"github.com/opengovern/og-task-syft/worker"
	"golang.org/x/net/context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(c)
		cancel()
	}()

	go func() {
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := worker.WorkerCommand().ExecuteContext(ctx); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
