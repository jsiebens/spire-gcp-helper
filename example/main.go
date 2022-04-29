package main

import (
	"cloud.google.com/go/storage"
	"context"
	"fmt"
	"github.com/jsiebens/spire-gcp-helper/pkg/spiregcp"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"log"
)

func main() {
	projectID := "YOUR_PROJECT_ID"
	projectNumber := "YOUR_PROJECT_NUMBER"
	serviceAccount := "YOUR_SERVICE_ACCOUNT_TO_IMPERSONATE"
	poolId := "YOUR_WORKLOAD_IDENTITY_POOL_ID"
	providerId := "YOUR_WORKLOAD_IDENTITY_PROVIDER_ID"

	ctx := context.Background()

	credentials := spiregcp.Credentials(serviceAccount, spiregcp.DefaultAudience(projectNumber, poolId, providerId))

	client, err := storage.NewClient(ctx, option.WithCredentials(credentials))
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	it := client.Buckets(ctx, projectID)
	for {
		battrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Failed to list buckets: %v", err)
		}
		fmt.Printf("Bucket: %v\n", battrs.Name)
	}
}
