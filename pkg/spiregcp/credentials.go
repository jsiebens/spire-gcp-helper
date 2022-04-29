package spiregcp

import (
	"fmt"
	"github.com/jsiebens/spiffe-gcp-helper/pkg/oauth2"
	"golang.org/x/oauth2/google"
)

func DefaultAudience(projectNumber, poolId, providerId string) string {
	return fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, poolId, providerId)
}

func Credentials(serviceAccount, audience string) *google.Credentials {
	config := oauth2.DefaultConfig(serviceAccount, audience)
	tokenSource := oauth2.SpiffeTokenSource(config)
	return &google.Credentials{TokenSource: tokenSource}
}
