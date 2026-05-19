"""
azure_blob.py — EVIDETH Azure Blob Storage service

Responsabilities:
  - Upload video files to Azure Blob Storage after verification.
  - Download video blobs back to a temp path for re-verification.
  - Generate short-lived SAS URLs for auditor access.
  - Delete blobs when a Video record is removed.

All methods are synchronous to stay compatible with the existing
Threading-based async job runner in verification.py.
"""
from __future__ import annotations

import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from azure.storage.blob import (
    BlobServiceClient,
    BlobClient,
    generate_blob_sas,
    BlobSasPermissions,
)
from azure.core.exceptions import ResourceNotFoundError

from app.config import settings

logger = logging.getLogger(__name__)

# ── Module-level singleton (lazy init) ──────────────────────────────────────
_blob_service_client: Optional[BlobServiceClient] = None


def _get_client() -> Optional[BlobServiceClient]:
    """Return (and lazily create) the BlobServiceClient.

    Returns None when AZURE_STORAGE_CONNECTION_STRING is not configured so
    the rest of the app can run without Azure in local/dev mode.
    """
    global _blob_service_client
    if _blob_service_client is not None:
        return _blob_service_client
    conn_str = settings.AZURE_STORAGE_CONNECTION_STRING
    if not conn_str:
        logger.warning(
            "AZURE_STORAGE_CONNECTION_STRING not set — Blob Storage disabled."
        )
        return None
    _blob_service_client = BlobServiceClient.from_connection_string(conn_str)
    return _blob_service_client


def _ensure_container() -> None:
    """Create the container if it does not exist yet."""
    client = _get_client()
    if client is None:
        return
    container_client = client.get_container_client(settings.AZURE_BLOB_CONTAINER)
    try:
        container_client.create_container()
        logger.info("Blob container '%s' created.", settings.AZURE_BLOB_CONTAINER)
    except Exception:
        # Container already exists — that is fine.
        pass


# ── Public API ───────────────────────────────────────────────────────────────

def upload_video(
    local_path: str,
    blob_name: str,
    overwrite: bool = True,
) -> Optional[str]:
    """Upload *local_path* to Azure Blob Storage.

    Args:
        local_path: Absolute path to the local video file.
        blob_name:  Target blob name, e.g. ``cameras/CAM-01/video_abc123.mp4``.
        overwrite:  Whether to overwrite an existing blob (default True).

    Returns:
        The blob URL on success, or None if Blob Storage is not configured.

    Raises:
        AzureError: On upload failure.
    """
    client = _get_client()
    if client is None:
        return None

    _ensure_container()

    blob_client: BlobClient = client.get_blob_client(
        container=settings.AZURE_BLOB_CONTAINER,
        blob=blob_name,
    )

    file_size = os.path.getsize(local_path)
    logger.info(
        "Uploading '%s' (%d bytes) → blob '%s'",
        local_path, file_size, blob_name,
    )

    with open(local_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=overwrite)

    url = blob_client.url
    logger.info("Upload complete: %s", url)
    return url


def download_video(blob_name: str, dest_path: str) -> bool:
    """Download *blob_name* to *dest_path*.

    Returns:
        True on success, False if the blob does not exist or Blob Storage
        is not configured.
    """
    client = _get_client()
    if client is None:
        return False

    blob_client = client.get_blob_client(
        container=settings.AZURE_BLOB_CONTAINER,
        blob=blob_name,
    )

    try:
        with open(dest_path, "wb") as f:
            stream = blob_client.download_blob()
            stream.readinto(f)
        logger.info("Downloaded blob '%s' → '%s'", blob_name, dest_path)
        return True
    except ResourceNotFoundError:
        logger.warning("Blob '%s' not found in Azure.", blob_name)
        return False


def delete_video(blob_name: str) -> bool:
    """Delete *blob_name* from Azure Blob Storage.

    Returns:
        True if deleted, False if not found or Blob Storage not configured.
    """
    client = _get_client()
    if client is None:
        return False

    blob_client = client.get_blob_client(
        container=settings.AZURE_BLOB_CONTAINER,
        blob=blob_name,
    )

    try:
        blob_client.delete_blob()
        logger.info("Deleted blob '%s'", blob_name)
        return True
    except ResourceNotFoundError:
        logger.warning("Blob '%s' not found — nothing to delete.", blob_name)
        return False


def generate_sas_url(
    blob_name: str,
    expiry_hours: int = 1,
) -> Optional[str]:
    """Return a short-lived read-only SAS URL for *blob_name*.

    Useful for giving auditors temporary access to a video without
    exposing the storage account key.

    Args:
        blob_name:    The blob to generate the SAS for.
        expiry_hours: How many hours the URL should remain valid (default 1).

    Returns:
        Full SAS URL, or None if Blob Storage is not configured.
    """
    client = _get_client()
    if client is None:
        return None

    # Extract account name and key from the connection string
    conn_str = settings.AZURE_STORAGE_CONNECTION_STRING
    account_name: Optional[str] = None
    account_key:  Optional[str] = None

    for part in conn_str.split(";"):
        if part.startswith("AccountName="):
            account_name = part.split("=", 1)[1]
        elif part.startswith("AccountKey="):
            account_key = part.split("=", 1)[1]

    if not account_name or not account_key:
        logger.error("Cannot parse account name/key from connection string.")
        return None

    expiry = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

    sas_token = generate_blob_sas(
        account_name=account_name,
        container_name=settings.AZURE_BLOB_CONTAINER,
        blob_name=blob_name,
        account_key=account_key,
        permission=BlobSasPermissions(read=True),
        expiry=expiry,
    )

    blob_client = client.get_blob_client(
        container=settings.AZURE_BLOB_CONTAINER,
        blob=blob_name,
    )
    url = f"{blob_client.url}?{sas_token}"
    logger.info("SAS URL generated for '%s' (expires in %dh)", blob_name, expiry_hours)
    return url


def blob_exists(blob_name: str) -> bool:
    """Return True if *blob_name* exists in the container."""
    client = _get_client()
    if client is None:
        return False
    blob_client = client.get_blob_client(
        container=settings.AZURE_BLOB_CONTAINER,
        blob=blob_name,
    )
    try:
        blob_client.get_blob_properties()
        return True
    except ResourceNotFoundError:
        return False
