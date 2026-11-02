"""Exception hierarchy. Each error carries a stable `code` used in logs and API responses."""
from __future__ import annotations


class RagSecError(Exception):
    code = "INTERNAL_ERROR"
    http_status = 500

    def __init__(self, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


# --- document ingestion -------------------------------------------------------
class DocumentError(RagSecError):
    code = "DOCUMENT_ERROR"
    http_status = 422


class EmptyDocumentError(DocumentError):
    code = "EMPTY_DOCUMENT"


class FileTooLargeError(DocumentError):
    code = "FILE_TOO_LARGE"
    http_status = 413


class UnsupportedFileTypeError(DocumentError):
    code = "UNSUPPORTED_FILE_TYPE"
    http_status = 415


class ContentTypeMismatchError(DocumentError):
    code = "CONTENT_TYPE_MISMATCH"
    http_status = 415


class EncryptedPdfError(DocumentError):
    code = "ENCRYPTED_PDF"


class DamagedPdfError(DocumentError):
    code = "DAMAGED_PDF"


class ScannedPdfError(DocumentError):
    code = "SCANNED_PDF_NO_TEXT"


class PageLimitError(DocumentError):
    code = "PAGE_LIMIT_EXCEEDED"
    http_status = 413


class TextLimitError(DocumentError):
    code = "TEXT_LIMIT_EXCEEDED"
    http_status = 413


class EncodingFailureError(DocumentError):
    code = "ENCODING_FAILURE"


class MetadataValidationError(DocumentError):
    code = "METADATA_INVALID"


# --- authorization / policy -----------------------------------------------------
class AuthenticationError(RagSecError):
    code = "UNAUTHENTICATED"
    http_status = 401


class AuthorizationFilterMissingError(RagSecError):
    """Raised when a retrieval would run without mandatory tenant/role constraints (fail closed)."""
    code = "AUTHZ_FILTER_MISSING"
    http_status = 403


class UnknownUserError(RagSecError):
    code = "UNKNOWN_USER"
    http_status = 403


class AuthorizationDeniedError(RagSecError):
    """Authenticated but not permitted (wrong capability, or acting as another user/tenant)."""
    code = "FORBIDDEN"
    http_status = 403


class PolicyValidationError(RagSecError):
    code = "POLICY_INVALID"
    http_status = 422


# --- index ----------------------------------------------------------------------
class IndexError_(RagSecError):
    code = "INDEX_ERROR"


class IndexValidationError(IndexError_):
    code = "INDEX_VALIDATION_FAILED"
    http_status = 409


class NoActiveIndexError(IndexError_):
    code = "NO_ACTIVE_INDEX"
    http_status = 409


# --- model serving ----------------------------------------------------------------
class ModelError(RagSecError):
    code = "MODEL_ERROR"
    http_status = 502


class ModelUnavailableError(ModelError):
    code = "MODEL_UNAVAILABLE"
    http_status = 503


class ModelNotFoundError(ModelError):
    code = "MODEL_NOT_FOUND"
    http_status = 503


class ModelTimeoutError(ModelError):
    code = "MODEL_TIMEOUT"
    http_status = 504


class ResourceExhaustedError(ModelError):
    code = "RESOURCE_EXHAUSTED"  # OOM / CUDA allocation failures
    http_status = 503


class MalformedModelResponseError(ModelError):
    code = "MALFORMED_MODEL_RESPONSE"


class DeadlineExceededError(RagSecError):
    code = "DEADLINE_EXCEEDED"
    http_status = 504


# --- guardrails -------------------------------------------------------------------
class PluginError(RagSecError):
    code = "PLUGIN_ERROR"


class PluginTimeoutError(PluginError):
    code = "PLUGIN_TIMEOUT"


# --- experiments ------------------------------------------------------------------
class ExperimentError(RagSecError):
    code = "EXPERIMENT_ERROR"
    http_status = 400


class DatasetError(ExperimentError):
    code = "DATASET_INVALID"


class JobNotFoundError(ExperimentError):
    code = "JOB_NOT_FOUND"
    http_status = 404
