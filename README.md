# Hybrid-cloud Object-Storage Operator

The hybrid-cloud-object-storage-operator is designed for hybrid-cloud, multi-teams kubernetes platforms to allow teams to deploy and manage their own object storages via kubernetes without cloud provider specific provisioning.

In classical cloud environments object storage would typically be managed by a central platform team via infrastructure automation like terraform. But this means when different teams are active on such a platform there exists a bottleneck because that central platform team must handle all requests for object storage buckets and accounts. With this operator teams in kubernetes gain the potential to manage buckets on their own. And because the operator integrates into the kubernetes API the teams have the same unified interface/API for all their deployments: Kubernetes YAMLs.

Additionally the operator also provides a consistent interface regardless of the environment (cloud provider, on-premise) the kubernetes cluster runs in. This means in usecases where teams have to deploy to clusters running in different environments they still get the same interface on all clusters and do not have to concern themselves with any differences.

Main features:

* Provides Kubernetes Custom resources for deploying and managing object storage buckets
* Abstracted, unified API regardless of target environment (cloud, on-premise)
* Currently supported backends:
  * Azure Storage Account blob services

Planned features:

* Support for AWS S3 backend
* Support for on-prem environments using MinIO
* New CRD to manage access to the buckets (other services/users can request read/write access to a bucket via separate credentials)

## Quickstart

To test out the operator you currently need an Azure account with a service principal and a kubernetes cluster (you can for example create a local one with [k3d](https://k3d.io/)) with cluter-admin permissions.

1. Run `helm repo add hybrid-cloud-object-storage-operator https://maibornwolff.github.io/hybrid-cloud-object-storage-operator/` to prepare the helm repository.
2. Prepare secret with azure credentials as `operator-creds.yaml` and apply it to the cluster (e.g. `kubectl apply -f operator-creds.yaml`):

    ```yaml
      apiVersion: v1
      kind: Secret
      type: Opaque
      metadata:
        name: hybrid-cloud-object-storage-operator-creds
        namespace: default
      stringData:
        AZURE_SUBSCRIPTION_ID: "<your-azure-subscription-id>"
        AZURE_TENANT_ID: "<your-azure-tenant-id>"
        AZURE_CLIENT_ID: "<service-principal-client-id>"
        AZURE_CLIENT_SECRET: "<service-principal-password>"
    ```

3. Prepare operator config as `operator-values.yaml`:

    ```yaml
      serviceAccount:
        create: true
      envSecret: hybrid-cloud-object-storage-operator-creds
      operatorConfig: |
        handler_on_resume: false
        backend: azureblob
        backends:
          azureblob:
            subscription_id: <your-azure-subscription-id>
            location: westeurope
            name_pattern: "<your-prefix>{name}"
            resource_group: <your-azure-resource-group>
            kind: StorageV2
            access_tier: Hot
            sku:
              name: "Standard_LRS"
            allow_anonymous_access: true
            parameters:
              network:
                public_access: true
    ```

4. Run `helm install hybrid-cloud-object-storage-operator-crds maibornwolff/hybrid-cloud-object-storage-operator-crds` to install the CRDs for the operator.
5. Run `helm install hybrid-cloud-object-storage-operator hybrid-cloud-object-storage-operator/hybrid-cloud-object-storage-operator -f operator-values.yaml` to install the operator.
6. Check if the pod of the operator is running and healthy: `kubectl get pods -l app.kubernetes.io/name=hybrid-cloud-object-storage-operator`.
7. Create your first bucket: `kubectl apply -f examples/azureblob.yaml`.
8. Check in azure to see if the new storage account is created.
9. Retrieve the credentials for the storage account: `kubectl get secretdemoteam-storage-credentials -o jsonpath="{.data.key}" | base64 -d`
10. After you are finished, delete the bucket again: `kubectl delete -f examples/azureblob.yaml`

## Operations Guide

To achieve its hybrid-cloud feature the operator abstracts between the generic API (Custom resource `ObjectStorageBucket`) and the concrete implementation for a specific cloud service. The concrete implementations are called backends. You can configure which backends should be active in the configuration. If you have several backends active the user can also select one.

The operator can be configured using a yaml-based config file. This is the complete configuration file with all options. Please refer to the comments in each line for explanations:

```yaml
handler_on_resume: false  # If set to true the operator will reconcile every available resource on restart even if there were no changes
backend: helmbitnami  # Default backend to use, required
allowed_backends: []  # List of backends the users can select from. If list is empty the default backend is always used regardless of if the user selects a backend 
backends:  # Configuration for the different backends. Required fields are only required if the backend is used
  azureblob:
    subscription_id: 1-2-3-4-5  # Azure Subscription id to provision storage account in, required
    location: westeurope  # Location to provision storage account in, required
    name_pattern: "{namespace}{name}"  # Pattern to use for naming storage accounts in azure. Variables {namespace} and {name} can be used and will be replaced by metadata.namespace and metadata.name of the custom object, required
    resource_group: foobar-rg  # Resource group to provision the storage account in, required
    delete_fake: false  # If enabled on delete the storage account will not actually be deleted but only be tagged, optional
    lock_from_deletion: false   # If enabled an azure lock will be set on the storage account object, requires owner permissions for the operator, optional
    tags: {}  # Extra tags to add to the storage account resource in Azure. variables {namespace} and {name} can be used, optional
    kind: StorageV2  # Kind to use for the storage accounts, optional
    access_tier: Hot  # Access tier for the storage accounts, can be Hot or Cold, optional
    sku:
      name: "Standard_LRS"  # Name of the SKU to use for the storage accounts
    allow_anonymous_access: false  # If set to true users can configure their storage accouts to allow anonymous access to blobs
    network:
      allow_azure_services: true  # If enabled a firewall rule will be added so that azure services can access the storage account, optional
      vnets:  # List of vnets the storage account should allow access from. Each vnet listed here must have Microsoft.Storage added to the ServiceEndpoints collection of the subnet, optional
        - vnet: foobar-vnet  # Name of the virtual network, required
          subnet: default  # Name of the subnet, required
    backup: # Configuration for use of Azure Backup Services
      vault_name: foobar-vault  # The name of the existing backup vault, make sure the Storage Account has the Role Assignment "Storage Account Backup Contributor" for the according vault
      policy_id: 123123123  # The policy within the backup vault to use
    parameters:  # Fields here define defaults for parameters also in the CRD and are used if the parameter is not set in the custom object supplied by the user
      network:
        public_access: false  # If set to true no network restrictions are placed on the storage account, if set to false access is only possible through vnet and firewall rules, optional
        firewall_rules:  # List of firewall rules to add to the storage account. Only take effect if public_access is set to false, optional
          - name: foobar  # Name of the rule, required
            cidr: 10.1.2.0/24  # CIDR (with a suffix of < 30) or single IP, required
      versioning:
        enabled: false  # If set to true data versioning will be enabled on the storage account
      delete_retention:
        enabled: false  # It set to true retention of deleted data will be enabled, optional
        days: 2  # Number of days to keep deleted data, optional
      sftp:  # SFTP feature can only be enabled for the first time at creation of the storage account. Background: The hierarchical namespace setting is needed for SFTP and will be used implicitly but it can be only set at creation time.
        enabled: false  # enable SFTP interface, optional
      backup:
        enabled: false  # If enabled, the storage accounts will be added to an existing backup vault by default. Backup instances will not be cleaned up with Object Storage Buckets for recovery purposes

```

Single configuration options can also be provided via environment variables, the complete path is concatenated using underscores, written in uppercase and prefixed with `HYBRIDCLOUD_`. As an example: `backends.azureblob.subscription_id` becomes `HYBRIDCLOUD_BACKENDS_AZUREBLOB_SUBSCRIPTION_ID`.

To protect storage accounts against accidential deletion you can enable `lock_from_deletion` in the azureblob backend. When enabled the operator will create a delete lock on the resource in Azure. Note that the operator will not remove that lock when the object in kubernetes is deleted, you have to do that yourself via either the Azure CLI or the Azure Portal so the operator can delete the storage account. If that is not done the kubernetes object cannot be deleted and any calls ala `kubectl delete` will hang until the lock is manually removed.
The azure backend also support a feature called `fake deletion` (via options `delete_fake`) where the storage accounts are not actually deleted but only tagged to mark it as deleted when the kubernetes custom object is deleted. This can be used in situations where the operator is freshly introduced in an environment where the users have little experience with this type of declarative management and you want to reduce the risk of accidental data loss.

For the azureblob backend there are several ways to protect the storage accounts from external access. One is on the network layer by disabling network access to the accounts from outside the cluster (via the `parameters.network.public_access` and `parameters.network.firewall_rules` and `network.vnets`) and the other is on the access layer by disallowing anonymous access (via `allow_anonymous_access`, this only gives the users the right to configure anonymous access, unless a user specifically does that only authenticated access is possible).

For the operator to interact with Azure it needs credentials. For local testing it can pick up the token from the azure cli but for real deployments it needs a dedicated service principal. Supply the credentials for the service principal using the environment variables `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` (if you deploy via the helm chart use the use `envSecret` value). Depending on the backend the operator requires the following azure permissions within the scope of the resource group it deploys to:

* `Microsoft.Storage/*`
* `Microsoft.Authorization/locks/*`, optional, if you want the operator to set delete locks

### Deployment

The operator can be deployed via helm chart:

1. Run `helm repo add hybrid-cloud-object-storage-operator https://maibornwolff.github.io/hybrid-cloud-object-storage-operator/` to prepare the helm repository.
2. Run `helm install hybrid-cloud-object-storage-operator-crds maibornwolff/hybrid-cloud-object-storage-operator-crds` to install the CRDs for the operator.
3. Run `helm install hybrid-cloud-object-storage-operator hybrid-cloud-object-storage-operator/hybrid-cloud-object-storage-operator -f values.yaml` to install the operator.

Configuration of the operator is done via helm values. For a full list of the available values see the [values.yaml in the chart](./helm/hybrid-cloud-object-storage-operator/values.yaml). These are the important ones:

* `operatorConfig`: overwrite this with your specific operator config
* `envSecret`: Name of a secret with sensitive credentials (e.g. Azure service principal credentials)
* `serviceAccount.create`: Either set this to true or create the serviceaccount with appropriate permissions yourself and set `serviceAccount.name` to its name

## User Guide

The operator is completely controlled via Kubernetes custom resources (`ObjectStorageBucket`). Once a bucket object is created the operator will utilize one of its backends to provision an actual object storage bucket.

The `ObjectStorageBucket` resource has the following options:

```yaml
apiVersion: hybridcloud.maibornwolff.de/v1alpha1
kind: ObjectStorageBucket
metadata:
  name: teamfoo  # Name of the bucket, based on this a name in the backend will be generated, required
  namespace: default  # Kubernetes namespace, required
spec:
  backend: azureblob  # Name of the backend to use, optional, should be left empty unless provided by the admin
  interface: azureblob  # Interface to use for the bucket, defaults to the native interface of the backend (Azure Storage API for azureblob), optional
  network:  # Network related features, optional
    publicAccess: false  # If set to false access to the bucket is only possible from inside the cluster and the network ranges specified under firewallRules, optional
    firewallRules:  # If the backend supports it a list of firewall rules to configure access from outside the cluster, optional
      - name: foobar  # Name of the rule, required
        cidr: 10.1.2.0/24  # CIDR (with a suffix of < 30) or single IP, required
  security:
    anonymousAccess: false  # It set to true anonymous access can be enabled for containers, optional
    cors:  # A list of CORS rules to configure for the bucket, relevant if the bucket is used as a sort of fileserver, optional
      - name: foobar  # Name of the CORS rule, required
        allowedOrigins:  # List of origins to allow, required
          - https://my.origin.site
        allowedMethods:  # List of HTTP methods to allow (must be one or more of ["DELETE", "GET", "HEAD", "MERGE", "OPTIONS", "PATCH", "POST", "PUT"]), required
          - GET
        exposedHeaders:  # List of HTTP headers to allow in the request, wildcard "*" is allowed, required
          - "*"
        allowedHeaders:  # List of HTTP headers to allow in the response, wildcard "*" is allowed, required
          - "*"
        maxAgeInSeconds: 200  # Time in seconds the bucket should cache Preflight-OPTIONS requests, required
  dataRetention:  # Settings related to data retention, optional
    versioning:  # Settings related to versioning, optional
      enabled: false  # Enable versioning in storage account, optional
    deleteRetention:  # Settings related to delete retention, optional
      enabled: false  # Enable retention on delete, optional
      retentionPeriodInDays: 1  # Days to keep deleted data, optional
  backup:
    enabled: false  # Override the default backup strategy configured in the global operator config
  containers:  # Only relevant for azure, list of containers to create in the bucket, for azure at least one is required, containers not on the list will be removed from the storage account, including their data
    - name: assets  # Name of the container, required
      anonymousAccess: false  # If set to true objects in the container can be accessed without authentication/authorization, only relevant if `security.anonymousAccess` is set to true, optional
  sftp:  # SFTP feature can only be enabled for the first time at creation of the storage account. Background: The hierarchical namespace setting is needed for SFTP and will be used implicitly but it can be only set at creation time.
    enabled: true  # enable SFTP interface, required
    users:  # creating users that can access the bucket via SFTP protocol
      - username: techuser  # username, required
        access:  # definition which ressources can be accessed by the user. Currently only blob resources are supported.
          - container: assets  # name of the container
            permissions:  # list of the operations a user can do. Possible values are READ, WRITE, DELETE, LIST, CREATE 
              - READ
              - LIST
        sshKeys:  # public key authentication is supported, required
          - description: just a sample description  # key description
            publicKey:  # public key, required
  credentialsSecret: teamfoo-storage-credentials  # Name of a secret where the credentials for the bucket should be stored, required
```

Depending on the operator configuration buckets by default are protected from external or unauthenticated (anonymous) access. If anonymous access is configured very often CORS must also be configured. For more details on CORS see the [AWS S3 CORS docs](https://docs.aws.amazon.com/de_de/AmazonS3/latest/userguide/ManageCorsUsing.html#cors-expose-headers) or the [Azure Storage CORS docs](https://docs.microsoft.com/en-us/rest/api/storageservices/cross-origin-resource-sharing--cors--support-for-the-azure-storage-services).

A service/application that wants to access the bucket should depend on the credentials secret and use its values for the connection. That way it is independent of the actual backend. Provided keys in the secret depend on the interface: For azure blob the fields are: `interface` (set to `azureblob`), `endpoint`, `key`, `connection_string` (connection string with key and endpoint as accepted by azure storage libraries).

If needed the access credentials for the bucket can be reset/rotated. Add a label `operator/action` with value `rotate-keys` to the bucket object in kubernetes. The operator will pick up the label, will rotate or regenerate the credentials, update the credentials secret and remove the label from the object to signal completion. You are responsible for restarting any applications/pods using the credentials.

## Development

The operator is implemented in Python using the [Kopf](https://github.com/nolar/kopf) ([docs](https://kopf.readthedocs.io/en/stable/)) framework.

To run it locally follow these steps:

1. Create and activate a local python virtualenv
2. Install dependencies: `pip install -r requirements.txt`
3. Setup a local kubernetes cluster, e.g. with k3d: `k3d cluster create`
4. Apply the CRDs in your local cluster: `kubectl apply -f helm/hybrid-cloud-object-storage-operator-crds/templates/`
5. If you want to deploy to azure: Either have the azure cli installed and configured with an active login or export the following environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
6. Adapt the `config.yaml` to suit your needs
7. Run `kopf run main.py -A`
8. In another window apply some objects to the cluster to trigger the operator (see the `examples` folder)

The code is structured in the following packages:

* `handlers`: Implements the operator interface for the provided custom resources, reacts to create/update/delete events in handler functions
* `backends`: Backends for the different environments (currently Azure)
* `util`: Helper and utility functions

### Tips and tricks

* Kopf marks every object it manages with a finalizer, that means that if the operator is down or doesn't work a `kubectl delete` will hang. To work around that edit the object in question (`kubectl edit <type> <name>`) and remove the finalizer from the metadata. After that you can normally delete the object. Note that in this case the operator will not take care of cleaning up any azure resources.
* If the operator encounters an exception while processing an event in a handler, the handler will be retried after a short back-off time. During the development you can then stop the operator, make changes to the code and start the operator again. Kopf will pick up again and rerun the failed handler.
* When a handler was successfull but you still want to rerun it you need to fake a change in the object being handled. The easiest is adding or changing a label.
