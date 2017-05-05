// Package v2action contains the business logic for the commands/v2 package
package v2action

// Warnings is a list of warnings returned back from the cloud controller
type Warnings []string

// Actor handles all business logic for Cloud Controller v2 operations.
type Actor struct {
	CloudControllerClient CloudControllerClient
	UAAClient             UAAClient
}

// NewActor returns a new actor.
func NewActor(ccClient CloudControllerClient, uaaClient UAAClient) *Actor {
	return &Actor{
		CloudControllerClient: ccClient,
		UAAClient:             uaaClient,
	}
}
