import string
from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.storage.models import StorageAccountCreateParameters, StorageAccountUpdateParameters, Sku, BlobServiceProperties, \
    CorsRules, CorsRule, NetworkRuleSet, IPRule, VirtualNetworkRule, BlobContainer, StorageAccountCheckNameAvailabilityParameters, StorageAccountRegenerateKeyParameters, \
    DeleteRetentionPolicy, RestorePolicyProperties, ChangeFeed
from azure.mgmt.resource.locks.models import ManagementLockObject
from ..util.azure import azure_client_storage, azure_client_locks
from ..config import config_get
from ..util.reconcile_helpers import field_from_spec


TAGS_PREFIX = "hybridcloud-object-storage-operator"
HTTP_METHODS = ["DELETE", "GET", "HEAD", "MERGE", "OPTIONS", "PATCH", "POST", "PUT"]


def _backend_config(key, default=None, fail_if_missing=False):
    return config_get(f"backends.azureblob.{key}", default=default, fail_if_missing=fail_if_missing)


def _calc_name(namespace, name):
    # Allow admins to override names so that existing storage accounts not following the schema can still be managed
    name_overrides = _backend_config("name_overrides", default=[])
    for override in name_overrides:
        if override["namespace"] == namespace and override["name"] == name:
            return override["azure_name"]
    # Use name pattern to calculate name
    calculated_name = _backend_config("name_pattern", fail_if_missing=True).format(namespace=namespace, name=name).lower()
    # Azure requires storage account names to only consist of numbers and lowercase letters
    return ''.join(filter(lambda el: el in string.ascii_lowercase+string.digits, calculated_name))


class AzureBlobBackend:
    def __init__(self, logger):
        self._logger = logger
        self._storage_client = azure_client_storage()
        self._lock_client = azure_client_locks()
        self._subscription_id = _backend_config("subscription_id", fail_if_missing=True)
        self._location = _backend_config("location", fail_if_missing=True)
        self._resource_group = _backend_config("resource_group", fail_if_missing=True)

    def bucket_spec_valid(self, namespace, name, spec):
        bucket_name = _calc_name(namespace, name)
        if len(bucket_name) > 24:
            return (False, f"calculated storage account name '{bucket_name}' is longer than 24 characters")
        if not self.bucket_exists(namespace, name):
            result = self._storage_client.storage_accounts.check_name_availability(StorageAccountCheckNameAvailabilityParameters(name=bucket_name))
            if not result.name_available:
                return (False, f"storage account name cannot be used: {result.reason}: {result.message}")
        return (True, "")

    def bucket_exists(self, namespace, name):
        bucket_name = _calc_name(namespace, name)
        try:
            return self._storage_client.storage_accounts.get_properties(self._resource_group, bucket_name)
        except ResourceNotFoundError:
            return False

    def create_or_update_bucket(self, namespace, name, spec):
        bucket_name = _calc_name(namespace, name)
        sku = Sku(name=_backend_config("sku.name", default="Standard_LRS"))
        public_access = field_from_spec(spec, "network.publicAccess", default=_backend_config("parameters.network.public_access", default=False))
        network_rules = self._map_network_rules(spec, public_access)
        tags = _calc_tags(namespace, name)

        try:
            storage_account = self._storage_client.storage_accounts.get_properties(self._resource_group, bucket_name)
        except:
            storage_account = None

        if not storage_account:
            # Create storage account
            parameters = StorageAccountCreateParameters(
                sku=sku,
                kind=_backend_config("kind", default="StorageV2"),
                location=self._location,
                tags=tags,
                public_network_access="Enabled",  # Disabled means only via endpoint connection,
                network_rule_set=network_rules,
                access_tier=_backend_config("access_tier", default="Hot"),
                enable_https_traffic_only=True,
                allow_blob_public_access=_backend_config("allow_anonymous_access", default=False),
                allow_shared_key_access=True,
            )
            self._storage_client.storage_accounts.begin_create(self._resource_group, bucket_name, parameters=parameters).result()
        else:
            # Update storage account
            parameters = StorageAccountUpdateParameters(
                tags=tags,
                public_network_access="Enabled",  # Disabled means only via endpoint connection
                network_rule_set=network_rules
            )
            self._storage_client.storage_accounts.update(self._resource_group, bucket_name, parameters=parameters)
        
        if _backend_config("lock_from_deletion", default=False):
            self._lock_client.management_locks.create_or_update_at_resource_level(self._resource_group, "Microsoft.Storage", "", "storageAccounts", bucket_name, "DoNotDeleteLock", parameters=ManagementLockObject(level="CanNotDelete", notes="Protection from accidental deletion"))

        # Create blob services
        retention, changefeed = _map_retention(spec)
        versioning = field_from_spec(spec, "dataRetention.versioning.enabled", default=_backend_config("parameters.versioning.enabled", default=False))
        parameters = BlobServiceProperties(
            cors=_map_cors_rules(spec.get("security", dict()).get("cors")),
            is_versioning_enabled=versioning,
            delete_retention_policy=retention,
            container_delete_retention_policy=retention,
            restore_policy=None,
            change_feed=changefeed,
        )
        self._storage_client.blob_services.set_service_properties(self._resource_group, bucket_name, parameters=parameters)
        
        # Create containers
        existing_containers = dict()
        for container in self._storage_client.blob_containers.list(self._resource_group, bucket_name):
            existing_containers[container.name] = container
        for container in spec.get("containers", []):
            public_access = "Blob" if container.get("anonymousAccess", False) else "None"
            parameters = BlobContainer(public_access=public_access)
            existing_container = existing_containers.pop(container["name"]) if container["name"] in existing_containers else None
            if not existing_container:
                self._storage_client.blob_containers.create(self._resource_group, bucket_name, container["name"], blob_container=parameters)
            elif existing_container.public_access != public_access:
                self._storage_client.blob_containers.update(self._resource_group, bucket_name, container["name"], blob_container=parameters)
        for container in existing_containers.values():
            if container.name.startswith("$"):
                # system containers, ignore
                continue
            self._storage_client.blob_containers.delete(self._resource_group, bucket_name, container.name)
        # Credentials
        for key in self._storage_client.storage_accounts.list_keys(self._resource_group, bucket_name).keys:
            if key.key_name == "key1":
                return {
                    "interface": "azureblob",
                    "endpoint": f"https://{bucket_name}.blob.core.windows.net",
                    "key": key.value,
                    "connection_string": f"DefaultEndpointsProtocol=https;AccountName={bucket_name};AccountKey={key.value};EndpointSuffix=core.windows.net",
                }
        raise Exception("Could not find keys in azure")

    def delete_bucket(self, namespace, name):
        bucket_name = _calc_name(namespace, name)
        delete_fake = _backend_config("delete_fake", default=False)
        if delete_fake:
            tags = _calc_tags(namespace, name, {"marked-for-deletion": "yes"})
            self._storage_client.storage_accounts.update(self._resource_group, bucket_name, parameters=StorageAccountUpdateParameters(tags=tags))
        else:
            self._storage_client.storage_accounts.delete(self._resource_group, bucket_name)

    def reset_credentials(self, namespace, name):
        bucket_name = _calc_name(namespace, name)
        self._storage_client.storage_accounts.regenerate_key(self._resource_group, bucket_name, StorageAccountRegenerateKeyParameters(key_name="key1"))
        # Credentials
        for key in self._storage_client.storage_accounts.list_keys(self._resource_group, bucket_name).keys:
            if key.key_name == "key1":
                return {
                    "interface": "azureblob",
                    "endpoint": f"https://{bucket_name}.blob.core.windows.net",
                    "key": key.value,
                    "connection_string": f"DefaultEndpointsProtocol=https;AccountName={bucket_name};AccountKey={key.value};EndpointSuffix=core.windows.net",
                }
        raise Exception("Could not find keys in azure") 

    def _map_network_rules(self, spec, public_access):
        ip_rules = []
        spec_rules = field_from_spec(spec, "network.firewallRules", [])
        extra_rules = _backend_config("parameters.network.firewall_rules", default=[])
        for rule in spec_rules + extra_rules:
            ip_rules.append(IPRule(ip_address_or_range=rule["cidr"], action="Allow"))
        virtual_network_rules = []
        for config in _backend_config("network.vnets", default=[]):
            vnet = config["vnet"]
            subnet = config["subnet"]
            resource_id = f"/subscriptions/{self._subscription_id}/resourceGroups/{self._resource_group}/providers/Microsoft.Network/virtualNetworks/{vnet}/subnets/{subnet}"
            virtual_network_rules.append(VirtualNetworkRule(virtual_network_resource_id=resource_id, action="Allow"))
        bypass = "AzureServices" if _backend_config("network.allow_azure_services", default=False) else None
        return NetworkRuleSet(
            bypass=bypass,
            resource_access_rules=[],
            virtual_network_rules=virtual_network_rules,
            ip_rules=ip_rules,
            default_action="Allow" if public_access else "Deny"
        )


def _map_cors_rules(cors):
    if not cors:
        return None
    rules = []
    for rule in cors:
        rules.append(CorsRule(
            allowed_origins=rule["allowedOrigins"],
            allowed_methods=list(filter(lambda el: el in HTTP_METHODS, rule["allowedMethods"])),
            max_age_in_seconds=int(rule["maxAgeInSeconds"]),
            exposed_headers=rule["exposedHeaders"],
            allowed_headers=rule["allowedHeaders"]
        ))
    return CorsRules(cors_rules=rules)


def _map_retention(spec):
    enabled = field_from_spec(spec, "dataRetention.deleteRetention.enabled", default=_backend_config("parameters.delete_retention.enabled", default=False))
    days = field_from_spec(spec, "dataRetention.deleteRetention.retentionPeriodInDays", default=_backend_config("parameters.delete_retention.days", default=1))
    retention = DeleteRetentionPolicy(
        enabled=enabled,
        days=days if enabled else None,
    )
    changefeed = ChangeFeed(
        enabled=False,
        retention_in_days=None,
    )
    return retention, changefeed



def _calc_tags(namespace, name, extra_tags={}):
    tags = {f"{TAGS_PREFIX}:namespace": namespace, f"{TAGS_PREFIX}:name": name}
    for k, v in extra_tags.items():
        tags[f"{TAGS_PREFIX}:{k}"] = v
    for k, v in _backend_config("tags", default={}).items():
        tags[k] = v.format(namespace=namespace, name=name)
    return tags
