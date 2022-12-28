import kopf
from .routing import bucket_backend
from ..config import config_get
from ..util.reconcile_helpers import ignore_control_label_change, process_action_label
from ..util import k8s
from ..util.constants import BACKOFF
from ..util.exceptions import DeletionWithBackupEnabledException


if config_get("handler_on_resume", default=False):
    @kopf.on.resume(*k8s.ObjectStorageBucket.kopf_on(), backoff=BACKOFF)
    def bucket_handler_resume(body, spec, status, meta, labels, name, namespace, diff, logger, **kwargs):
        bucket_handler(body, spec, status, meta, labels, name, namespace, diff, logger, **kwargs)


@kopf.on.create(*k8s.ObjectStorageBucket.kopf_on(), backoff=BACKOFF)
@kopf.on.update(*k8s.ObjectStorageBucket.kopf_on(), backoff=BACKOFF)
def bucket_handler(body, spec, status, meta, labels, name, namespace, diff, logger, **kwargs):
    if ignore_control_label_change(diff):
        logger.debug("Only control labels removed. Nothing to do.")
        return

    backend, backend_name = _get_backend(status, spec, logger)

    valid, reason = backend.bucket_spec_valid(namespace, name, spec)
    if not valid:
        _status(name, namespace, status, "failed", f"Validation failed: {reason}")
        raise kopf.PermanentError("Spec is invalid, check status for details")

    logger.info("Creating/Updating bucket")
    _status(name, namespace, status, "working", backend=backend_name)
    # create bucket
    credentials = backend.create_or_update_bucket(namespace, name, spec)
    logger.info("Created/updated bucket. Creating credentials secret")

    def action_reset_keys():
        nonlocal credentials
        credentials = backend.reset_credentials(namespace, name)
        return "Access tokens rotated"
    process_action_label(labels, {
        "rotate-keys": action_reset_keys,
    }, body, k8s.ObjectStorageBucket)

    # store credentials in secret
    k8s.create_or_update_secret(namespace, spec["credentialsSecret"], credentials)
    # mark success
    _status(name, namespace, status, "finished", "Bucket created", backend=backend_name)


@kopf.on.delete(*k8s.ObjectStorageBucket.kopf_on(), backoff=BACKOFF)
def bucket_delete(spec, status, name, namespace, logger, **_):
    backend, _ = _get_backend(status, spec, logger)

    if backend.bucket_exists(namespace, name):
        logger.info("Deleting bucket")
        try:
            backend.delete_bucket(namespace, name)
        except DeletionWithBackupEnabledException as e:
            reason = str(e)
            _status(name, namespace, status, "failed", f"Deletion failed: {reason}")
            raise kopf.TemporaryError(reason)
            
    else:
        logger.info("Bucket does not exist. Not doing anything")
    k8s.delete_secret(namespace, spec["credentialsSecret"])

@kopf.on.validate(*k8s.ObjectStorageBucket.kopf_on())
def validate_object_storage_spec(namespace, name, spec, status, logger, **_):
    backend, _ = _get_backend(status, spec, logger)
    valid, reason = backend.bucket_spec_valid(namespace, name, spec)

    if not valid:
       raise kopf.AdmissionError(reason)


def _get_backend(status, spec, logger):
    if status and "backend" in status:
        backend_name = status["backend"]
    else:
        backend_name = spec.get("backend", config_get("backend", fail_if_missing=True))
    return bucket_backend(backend_name, logger), backend_name

def _status(name, namespace, status_obj, status, reason=None, backend=None):
    if status_obj:
        status_obj = dict(backend=status_obj.get("backend", None))
    else:
        status_obj = dict()
    if backend:
        status_obj["backend"] = backend
    status_obj["deployment"] = {
        "status": status,
        "reason": reason
    }
    k8s.patch_custom_object_status(k8s.ObjectStorageBucket, namespace, name, status_obj)
