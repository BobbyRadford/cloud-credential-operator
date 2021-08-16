package ibmcloud

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/iampolicymanagementv1"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/yaml"

	credreqv1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	v1 "github.com/openshift/cloud-credential-operator/pkg/apis/cloudcredential/v1"
	"github.com/openshift/cloud-credential-operator/pkg/cmd/provisioning"
)

const (
	secretManifestsTemplate = `apiVersion: v1
stringData:
  ibmcloud_api_key: %s
kind: Secret
metadata:
  name: %s
  namespace: %s
type: Opaque`

	manifestsDirName = "manifests"
)

// APIKeyEnvVars is a list of environment variable names containing an IBM Cloud API key
var APIKeyEnvVars = []string{"IC_API_KEY", "IBMCLOUD_API_KEY", "BM_API_KEY", "BLUEMIX_API_KEY"}

var (
	// CreateOpts captures the options that affect creation of the generated
	// objects.
	CreateOpts = options{
		TargetDir: "",
	}
)

// getEnv reads the content from first found environment variable from the envs list, returns empty string if none found.
func getEnv(envs []string) string {
	for _, k := range envs {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// NewCreateIAMPoliciesCmd provides the "create-shared-secrets" subcommand
func NewCreateSharedSecretsCmd() *cobra.Command {
	createSharedSecretsCmd := &cobra.Command{
		Use:              "create-shared-secrets",
		Short:            "Create shared secrets",
		RunE:             createSharedSecretsCmd,
		PersistentPreRun: initEnvForCreateIAMPoliciesCmd,
	}

	createSharedSecretsCmd.PersistentFlags().StringVar(&CreateOpts.Name, "name", "", "User-define name for all created IBM Cloud resources (can be separate from the cluster's infra-id)")
	createSharedSecretsCmd.MarkPersistentFlagRequired("name")
	createSharedSecretsCmd.PersistentFlags().StringVar(&CreateOpts.CredRequestDir, "credentials-requests-dir", "", "Directory containing files of CredentialsRequests to create IAM Roles for (can be created by running 'oc adm release extract --credentials-requests --cloud=aws' against an OpenShift release image)")
	createSharedSecretsCmd.MarkPersistentFlagRequired("credentials-requests-dir")
	createSharedSecretsCmd.PersistentFlags().StringVar(&CreateOpts.ResourceGroupID, "resource-group-id", "", "ID of the resource group used for scopping the access policies")
	createSharedSecretsCmd.PersistentFlags().BoolVar(&CreateOpts.DryRun, "dry-run", false, "Skip creating objects, and just save what would have been created into files")
	createSharedSecretsCmd.PersistentFlags().StringVar(&CreateOpts.TargetDir, "output-dir", "", "Directory to place generated files (defaults to current directory)")

	return createSharedSecretsCmd
}

func createSharedSecretsCmd(cmd *cobra.Command, args []string) error {
	apiKey := getEnv(APIKeyEnvVars)
	if apiKey == "" {
		log.Fatalf("%s environment variable not set", APIKeyEnvVars)
	}
	authenticator := &core.IamAuthenticator{
		ApiKey: apiKey,
	}

	err := authenticator.Validate()
	if err != nil {
		return err
	}

	// Setup the IAM Policy Management SDK.
	options := &iampolicymanagementv1.IamPolicyManagementV1Options{
		Authenticator: authenticator,
	}
	iamPolicyManagementSvc, err := iampolicymanagementv1.NewIamPolicyManagementV1(options)
	if err != nil {
		return err
	}
	userAgentString := "OpenShift/4.x Cloud Credential Operator"
	iamPolicyManagementSvc.Service.SetUserAgent(userAgentString)

	// Setup the IAM Identity SDK.
	iamIdentitySvc, err := iamidentityv1.NewIamIdentityV1(&iamidentityv1.IamIdentityV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return err
	}
	iamIdentitySvc.Service.SetUserAgent(userAgentString)

	// Get details from the provided API key.
	apiKeyDetails, err := getAuthenticatorAPIKeyDetails(iamIdentitySvc, authenticator)
	if err != nil {
		return err
	}

	err = createSharedSecrets(iamPolicyManagementSvc,
		iamIdentitySvc,
		apiKeyDetails,
		CreateOpts.ResourceGroupID,
		CreateOpts.CredRequestDir,
		CreateOpts.TargetDir,
		CreateOpts.DryRun)
	if err != nil {
		return err
	}

	return nil
}

func createSharedSecrets(iamSvc *iampolicymanagementv1.IamPolicyManagementV1,
	iamIdentitySvc *iamidentityv1.IamIdentityV1,
	apiKeyDetails *iamidentityv1.APIKey,
	resourceGroupID string,
	credReqDir string,
	targetDir string,
	dryRun bool) error {

	// Process directory
	credReqs, err := getListOfCredentialsRequests(credReqDir)
	if err != nil {
		return errors.Wrap(err, "Failed to process files containing CredentialsRequests")
	}

	// Create IAM Service ID, Access Policies, and write Secrets
	if err := processCredentialsRequests(
		iamSvc,
		iamIdentitySvc,
		credReqs,
		apiKeyDetails,
		resourceGroupID,
		targetDir,
		dryRun); err != nil {
		return errors.Wrap(err, "Failed while processing each CredentialsRequest")
	}

	return nil
}

func processCredentialsRequests(iamPolicyManagementSvc *iampolicymanagementv1.IamPolicyManagementV1,
	iamIdentitySvc *iamidentityv1.IamIdentityV1,
	credReqs []*v1.CredentialsRequest,
	apiKeyDetails *iamidentityv1.APIKey,
	resourceGroupID string,
	targetDir string,
	dryRun bool) error {

	for _, cr := range credReqs {
		// Decode IBMCloudProviderSpec
		codec, err := credreqv1.NewCodec()
		if err != nil {
			return errors.Wrap(err, "Failed to create credReq codec")
		}

		ibmcloudProviderSpec := v1.IBMCloudProviderSpec{}
		if err := codec.DecodeProviderSpec(cr.Spec.ProviderSpec, &ibmcloudProviderSpec); err != nil {
			return errors.Wrap(err, "Failed to decode the provider spec")
		}

		if ibmcloudProviderSpec.Kind != "IBMCloudProviderSpec" {
			return fmt.Errorf("CredentialsRequest %s/%s is not of type IBMCloud", cr.Namespace, cr.Name)
		}

		// Create a new IAM Service ID for this CredReq.
		serviceIDName := fmt.Sprintf("%s-%s-%s", CreateOpts.Name, cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
		serviceID, err := createServiceID(iamIdentitySvc, *apiKeyDetails.AccountID, serviceIDName)
		if err != nil {
			return errors.Wrap(err, "Failed to create Service ID")
		}
		log.Printf("Created IAM Service ID %q", *serviceID.IamID)

		// Create a new Access Policy for each policy in the CredReq.
		for _, policy := range ibmcloudProviderSpec.Policies {
			err = createPolicy(iamPolicyManagementSvc, cr, &policy, *apiKeyDetails.AccountID, serviceID, resourceGroupID, targetDir, dryRun)
			if err != nil {
				return errors.Wrap(err, "Failed to create access policy")
			}
		}

		if CreateOpts.ResourceGroupID != "" {
			// If scoped to a resource group, we must create the implicit "Viewer" access
			// policy on the resource group itself.
			err = createImplicitResourceGroupViewerPolicy(iamPolicyManagementSvc, *apiKeyDetails.AccountID, *serviceID.IamID, resourceGroupID)
			if err != nil {
				return errors.Wrap(err, "Failed to create implicit resource group Viewer access policy")
			}
		}

		// Create a new API Key for the Service ID.
		options := iamIdentitySvc.NewCreateAPIKeyOptions("ccoctl-generated-key", *serviceID.IamID)
		apiKey, _, err := iamIdentitySvc.CreateAPIKey(options)
		if err != nil {
			return errors.Wrap(err, "Failed to create Service ID API key")
		}

		// Write the CredReq secret containing the new API key.
		if err := writeCredReqSecret(cr, targetDir, *apiKey.Apikey); err != nil {
			return errors.Wrap(err, "failed to save Secret for install manifests")
		}
	}
	return nil
}

func getListOfCredentialsRequests(dir string) ([]*credreqv1.CredentialsRequest, error) {
	credRequests := []*credreqv1.CredentialsRequest{}
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		f, err := os.Open(filepath.Join(dir, file.Name()))
		if err != nil {
			return nil, errors.Wrap(err, "Failed to open file")
		}
		defer f.Close()
		decoder := yaml.NewYAMLOrJSONDecoder(f, 4096)
		for {
			cr := &credreqv1.CredentialsRequest{}
			if err := decoder.Decode(cr); err != nil {
				if err == io.EOF {
					break
				}
				return nil, errors.Wrap(err, "Failed to decode to CredentialsRequest")
			}
			credRequests = append(credRequests, cr)
		}

	}

	return credRequests, nil
}

func writeCredReqSecret(cr *credreqv1.CredentialsRequest, targetDir, apiKey string) error {
	manifestsDir := filepath.Join(targetDir, manifestsDirName)

	fileName := fmt.Sprintf("%s-%s-credentials.yaml", cr.Spec.SecretRef.Namespace, cr.Spec.SecretRef.Name)
	filePath := filepath.Join(manifestsDir, fileName)

	fileData := fmt.Sprintf(secretManifestsTemplate, apiKey, cr.Spec.SecretRef.Name, cr.Spec.SecretRef.Namespace)

	if err := ioutil.WriteFile(filePath, []byte(fileData), 0600); err != nil {
		return errors.Wrap(err, "Failed to save Secret file")
	}

	log.Printf("Saved credentials configuration to: %s", filePath)

	return nil
}

// initEnvForCreateIAMPoliciesCmd will ensure the destination directory is ready to receive the generated
// files, and will create the directory if necessary.
func initEnvForCreateIAMPoliciesCmd(cmd *cobra.Command, args []string) {
	if CreateOpts.TargetDir == "" {
		pwd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current directory: %s", err)
		}

		CreateOpts.TargetDir = pwd
	}

	fPath, err := filepath.Abs(CreateOpts.TargetDir)
	if err != nil {
		log.Fatalf("Failed to resolve full path: %s", err)
	}

	// create target dir if necessary
	err = provisioning.EnsureDir(fPath)
	if err != nil {
		log.Fatalf("failed to create target directory at %s", fPath)
	}

	// create manifests dir if necessary
	manifestsDir := filepath.Join(fPath, manifestsDirName)
	err = provisioning.EnsureDir(manifestsDir)
	if err != nil {
		log.Fatalf("failed to create manifests directory at %s", manifestsDir)
	}
}

func createServiceID(iamIdentitySvc *iamidentityv1.IamIdentityV1, accountID string, name string) (*iamidentityv1.ServiceID, error) {
	options := iamIdentitySvc.NewCreateServiceIDOptions(accountID, name)
	serviceID, _, err := iamIdentitySvc.CreateServiceID(options)
	return serviceID, err
}

func createPolicy(iamPolicySvc *iampolicymanagementv1.IamPolicyManagementV1,
	credReq *v1.CredentialsRequest,
	policy *v1.AccessPolicy,
	accountID string,
	serviceID *iamidentityv1.ServiceID,
	resourceGroupName string,
	targetDir string,
	dryRun bool) error {

	// Construct the subjects with the newly created Service ID.
	subjects := []iampolicymanagementv1.PolicySubject{
		{
			Attributes: []iampolicymanagementv1.SubjectAttribute{
				{
					Name:  core.StringPtr("iam_id"),
					Value: core.StringPtr(*serviceID.IamID),
				},
			},
		},
	}

	// Construct the access policy's roles.
	roles := make([]iampolicymanagementv1.PolicyRole, len(policy.Roles))
	for i, role := range policy.Roles {
		roles[i] = iampolicymanagementv1.PolicyRole{
			RoleID: core.StringPtr(role),
		}
	}

	// Construct the access policy's resource attributes.
	resourceAttributes := make([]iampolicymanagementv1.ResourceAttribute, len(policy.Attributes))
	for i, attr := range policy.Attributes {
		resourceAttributes[i] = iampolicymanagementv1.ResourceAttribute{
			Name:  core.StringPtr(attr.Name),
			Value: core.StringPtr(attr.Value),
		}
	}

	// Append the resource group attribute if specified as a command line argument.
	if CreateOpts.ResourceGroupID != "" {
		resourceAttributes = append(resourceAttributes, iampolicymanagementv1.ResourceAttribute{
			Name:  core.StringPtr("resourceGroupId"),
			Value: core.StringPtr(CreateOpts.ResourceGroupID),
		})
	}

	// Append the required accountId attribute.
	resourceAttributes = append(resourceAttributes, iampolicymanagementv1.ResourceAttribute{
		Name:  core.StringPtr("accountId"),
		Value: core.StringPtr(accountID),
	})

	resources := []iampolicymanagementv1.PolicyResource{{
		Attributes: resourceAttributes,
	}}

	// Create the access policy.
	options := iamPolicySvc.NewCreatePolicyOptions("access", subjects, roles, resources)
	iamAccessPolicy, _, err := iamPolicySvc.CreatePolicy(options)
	if err != nil {
		return errors.Wrap(err, "Failed to create policy")
	}

	apJSON, _ := json.MarshalIndent(iamAccessPolicy, "", "  ")
	log.Printf("Created IAM Access Policy:\n%s", apJSON)

	return nil
}

func createImplicitResourceGroupViewerPolicy(iamSvc *iampolicymanagementv1.IamPolicyManagementV1,
	accountID string,
	serviceIDIamID string,
	resourceGroupID string,
) error {
	// Construct the subjects with the newly created Service ID.
	subjects := []iampolicymanagementv1.PolicySubject{
		{
			Attributes: []iampolicymanagementv1.SubjectAttribute{
				{
					Name:  core.StringPtr("iam_id"),
					Value: core.StringPtr(serviceIDIamID),
				},
			},
		},
	}

	// Construct the access policy's roles.
	roles := []iampolicymanagementv1.PolicyRole{
		{
			RoleID: core.StringPtr("crn:v1:bluemix:public:iam::::role:Viewer"),
		},
	}

	// Construct the access policy's resource attributes.
	resources := []iampolicymanagementv1.PolicyResource{{
		Attributes: []iampolicymanagementv1.ResourceAttribute{
			{
				Name:  core.StringPtr("resourceGroupId"),
				Value: core.StringPtr(resourceGroupID),
			},
			{
				Name:  core.StringPtr("accountId"),
				Value: core.StringPtr(accountID),
			},
		},
	}}

	// Create the access policy.
	options := iamSvc.NewCreatePolicyOptions("access", subjects, roles, resources)
	iamAccessPolicy, _, err := iamSvc.CreatePolicy(options)
	if err != nil {
		return errors.Wrap(err, "Failed to create policy")
	}

	apJSON, _ := json.MarshalIndent(iamAccessPolicy, "", "  ")
	log.Printf("Created IAM Access Policy:\n%s", apJSON)

	return nil
}

// getAuthenticatorAPIKeyDetails gets detailed information on the API key used
// for authentication to the IBM Cloud APIs
func getAuthenticatorAPIKeyDetails(iamIdentitySvc *iamidentityv1.IamIdentityV1, authenticator *core.IamAuthenticator) (*iamidentityv1.APIKey, error) {
	iamIdentityService, err := iamidentityv1.NewIamIdentityV1(&iamidentityv1.IamIdentityV1Options{
		Authenticator: authenticator,
	})
	if err != nil {
		return nil, err
	}

	options := iamIdentityService.NewGetAPIKeysDetailsOptions()
	options.SetIamAPIKey(authenticator.ApiKey)
	details, _, err := iamIdentityService.GetAPIKeysDetails(options)
	if err != nil {
		return nil, err
	}
	return details, nil
}
