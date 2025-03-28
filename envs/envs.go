package envs

import (
	"github.com/opengovern/opensecurity/services/tasks/worker/consts"
	"os"
)

var (
	NatsURL         = os.Getenv(consts.NatsURLEnv)
	NatsConsumer    = os.Getenv(consts.NatsConsumerEnv)
	StreamName      = os.Getenv(consts.NatsStreamNameEnv)
	TopicName       = os.Getenv(consts.NatsTopicNameEnv)
	ResultTopicName = os.Getenv(consts.NatsResultTopicNameEnv)

	ESAddress       = os.Getenv(consts.ElasticSearchAddressEnv)
	ESUsername      = os.Getenv(consts.ElasticSearchUsernameEnv)
	ESPassword      = os.Getenv(consts.ElasticSearchPasswordEnv)
	ESIsOnAks       = os.Getenv(consts.ElasticSearchIsOnAksNameEnv)
	ESIsOpenSearch  = os.Getenv(consts.ElasticSearchIsOpenSearch)
	ESAwsRegion     = os.Getenv(consts.ElasticSearchAwsRegionEnv)
	ESAssumeRoleArn = os.Getenv(consts.ElasticSearchAssumeRoleArnEnv)

	InventoryServiceEndpoint = os.Getenv(consts.InventoryBaseURL)
)
