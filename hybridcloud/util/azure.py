from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.resource import ManagementLockClient
from ..config import get_one_of


def _subscription_id():
    return get_one_of("backends.azureblob.subscription_id", "backends.azure.subscription_id", fail_if_missing=True)


def _credentials():
    return DefaultAzureCredential()


def azure_client_storage():
    return StorageManagementClient(_credentials(), _subscription_id())


def azure_client_locks():
    return ManagementLockClient(_credentials(), _subscription_id())
