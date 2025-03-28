package results

import (
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/runtime/protoimpl"
	"os"
	"time"
)

var (
	GRPCServerURL = os.Getenv("GRPC_SERVER_URL")
)

// function to send data with grpc
type ResponseOK struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func SendGRPC(ctx context.Context, data []byte, logger *zap.Logger) error {
	// create a grpc connection
	// send the data to the grpc server
	// the grpc server will save the data to the database
	// create a grpc connection
	grpcCtx := metadata.NewOutgoingContext(ctx, metadata.New(map[string]string{}))
	var client grpc.ClientConnInterface

	logger.Info("Setting grpc connection opts")
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	for retry := 0; retry < 5; retry++ {
		conn, err := grpc.NewClient(
			GRPCServerURL,
			opts...,
		)
		if err != nil {
			logger.Error("[result delivery] connection failure:", zap.Error(err))
			if retry == 4 {
				return err
			}
			time.Sleep(1 * time.Second)
			continue
		}
		client = conn

		break
	}
	for retry := 0; retry < 5; retry++ {
		// send the data to the grpc server
		out := new(ResponseOK)
		err := client.Invoke(grpcCtx, "/Tasks/Results", data, out)
		if err != nil {
			logger.Error("[result delivery] failed to send result:", zap.Error(err))
		}
		if retry == 4 {
			return err
		}
		time.Sleep(1 * time.Second)
		continue
	}

	return nil

}
