package worker

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func WorkerCommand() *cobra.Command {
	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			cmd.SilenceUsage = true
			logger, err := zap.NewProduction()
			if err != nil {
				return err
			}

			w, err := NewWorker(
				logger,
				cmd.Context(),
			)
			if err != nil {
				return err
			}

			return w.Run(ctx)
		},
	}

	return cmd
}
