package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/opengovern/og-task-syft/envs"
	"github.com/opengovern/og-task-syft/task"
	"github.com/opengovern/og-util/pkg/jq"
	"github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	"github.com/opengovern/og-util/pkg/tasks"
	"github.com/opengovern/opensecurity/services/tasks/db/models"
	"github.com/opengovern/opensecurity/services/tasks/scheduler"
	"go.uber.org/zap"
	"strconv"
	"time"
)

type Worker struct {
	logger   *zap.Logger
	jq       *jq.JobQueue
	esClient opengovernance.Client
}

func NewWorker(
	logger *zap.Logger,
	ctx context.Context,
) (*Worker, error) {
	jq, err := jq.New(envs.NatsURL, logger)
	if err != nil {
		logger.Error("failed to create job queue", zap.Error(err), zap.String("url", envs.NatsURL))
		return nil, err
	}

	logger.Info("Subscribing to stream", zap.String("stream", envs.StreamName),
		zap.Strings("topics", []string{envs.TopicName, envs.ResultTopicName}))
	if err := jq.Stream(ctx, envs.StreamName, "task job queue", []string{envs.TopicName, envs.ResultTopicName}, 100); err != nil {
		logger.Error("failed to create stream", zap.Error(err))
		return nil, err
	}

	isOnAks := false
	isOnAks, _ = strconv.ParseBool(envs.ESIsOnAks)
	isOpenSearch := false
	isOpenSearch, _ = strconv.ParseBool(envs.ESIsOpenSearch)

	esClient, err := opengovernance.NewClient(opengovernance.ClientConfig{
		Addresses:     []string{envs.ESAddress},
		Username:      &envs.ESUsername,
		Password:      &envs.ESPassword,
		IsOnAks:       &isOnAks,
		IsOpenSearch:  &isOpenSearch,
		AwsRegion:     &envs.ESAwsRegion,
		AssumeRoleArn: &envs.ESAssumeRoleArn,
	})
	if err != nil {
		return nil, err
	}

	w := &Worker{
		logger:   logger,
		jq:       jq,
		esClient: esClient,
	}

	return w, nil
}

func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("starting to consume", zap.String("url", envs.NatsURL), zap.String("consumer", envs.NatsConsumer),
		zap.String("stream", envs.StreamName), zap.String("topic", envs.TopicName))

	consumeCtx, err := w.jq.ConsumeWithConfig(ctx, envs.NatsConsumer, envs.StreamName, []string{envs.TopicName}, jetstream.ConsumerConfig{
		Replicas:          1,
		AckPolicy:         jetstream.AckExplicitPolicy,
		DeliverPolicy:     jetstream.DeliverAllPolicy,
		MaxAckPending:     -1,
		AckWait:           time.Minute * 30,
		InactiveThreshold: time.Hour,
	}, []jetstream.PullConsumeOpt{
		jetstream.PullMaxMessages(1),
	}, func(msg jetstream.Msg) {
		w.logger.Info("received a new job")
		w.logger.Info("committing")
		if err := msg.InProgress(); err != nil {
			w.logger.Error("failed to send the initial in progress message", zap.Error(err), zap.Any("msg", msg))
		}
		ticker := time.NewTicker(15 * time.Second)
		go func() {
			for range ticker.C {
				if err := msg.InProgress(); err != nil {
					w.logger.Error("failed to send an in progress message", zap.Error(err), zap.Any("msg", msg))
				}
			}
		}()

		err := w.ProcessMessage(ctx, msg)
		if err != nil {
			w.logger.Error("failed to process message", zap.Error(err))
		}
		ticker.Stop()

		if err := msg.Ack(); err != nil {
			w.logger.Error("failed to send the ack message", zap.Error(err), zap.Any("msg", msg))
		}

		w.logger.Info("processing a job completed")
	})
	if err != nil {
		return err
	}

	w.logger.Info("consuming")

	<-ctx.Done()
	consumeCtx.Drain()
	consumeCtx.Stop()

	return nil
}

func (w *Worker) ProcessMessage(ctx context.Context, msg jetstream.Msg) (err error) {
	var request tasks.TaskRequest
	if err := json.Unmarshal(msg.Data(), &request); err != nil {
		w.logger.Error("Failed to unmarshal ComplianceReportJob results", zap.Error(err))
		return err
	}

	response := &scheduler.TaskResponse{
		RunID:  request.TaskDefinition.RunID,
		Status: models.TaskRunStatusInProgress,
	}
	var responseJson []byte

	canceled := false
	ctxWithCancel, cancel := context.WithCancel(ctx)
	cancelSubject := tasks.GetTaskRunCancelSubject(envs.TopicName, request.TaskDefinition.RunID)
	subscription, err := w.jq.Subscribe(cancelSubject, func(m *nats.Msg) {
		canceled = true
		cancel()
	})
	if err != nil {
		w.logger.Error("failed to subscribe to results", zap.Error(err))
		return err
	} else {
		defer func() {
			sErr := subscription.Unsubscribe()
			if sErr != nil {
				w.logger.Error("failed to unsubscribe from results", zap.Error(sErr))
			}
		}()
	}

	defer func() {
		if canceled {
			response.Status = models.TaskRunStatusCancelled
		} else if err != nil {
			response.FailureMessage = err.Error()
			response.Status = models.TaskRunStatusFailed
		} else {
			response.Status = models.TaskRunStatusFinished
		}

		responseJson, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			w.logger.Error("failed to create job result json", zap.Error(marshalErr))
			return
		}

		if _, err := w.jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-result-%d", request.TaskDefinition.RunID)); err != nil {
			w.logger.Error("failed to publish job result", zap.String("jobResult", string(responseJson)), zap.Error(err))
		}
	}()

	responseJson, err = json.Marshal(response)
	if err != nil {
		w.logger.Error("failed to create response json", zap.Error(err))
		return err
	}

	if _, err = w.jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-inprogress-%d", request.TaskDefinition.RunID)); err != nil {
		w.logger.Error("failed to publish job in progress", zap.String("response", string(responseJson)), zap.Error(err))
	}

	err = task.RunTask(ctxWithCancel, w.jq, envs.InventoryServiceEndpoint, w.esClient, w.logger, request, response)
	if err != nil {
		w.logger.Error("failed to publish job result", zap.String("response", string(responseJson)), zap.Error(err))
		return err
	}
	response.Status = models.TaskRunStatusFinished

	return nil
}
