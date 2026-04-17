import argparse
import logging
import os
from typing import Optional

from src.security import BlobStorageManager, KeyVaultSecretProvider, SecuritySettings

logger = logging.getLogger("cyberguard.ingestion")


def _build_blob_clients():
    settings = SecuritySettings.from_env()
    secret_provider = KeyVaultSecretProvider.from_settings(settings, logger=logger)
    blob_storage = BlobStorageManager.from_settings(settings, secret_provider=secret_provider, logger=logger)
    return settings, blob_storage


def _resolve_blob_path(settings: SecuritySettings, category: str, relative_blob_path: str) -> str:
    clean_relative = relative_blob_path.strip().lstrip("/")
    if category == "raw":
        return settings.raw_blob_path(clean_relative)
    if category == "processed":
        return settings.processed_blob_path(clean_relative)
    return f"{settings.blob_logs_prefix}/{clean_relative}"


def upload_dataset(local_path: str, category: str, blob_path: Optional[str]) -> int:
    settings, blob_storage = _build_blob_clients()

    if not blob_storage.enabled:
        print("Blob storage is not configured. Upload skipped.")
        return 1

    if not os.path.exists(local_path):
        print(f"Local file not found: {local_path}")
        return 1

    resolved_blob_relative = blob_path or f"datasets/{os.path.basename(local_path)}"
    resolved_blob_path = _resolve_blob_path(settings, category, resolved_blob_relative)

    uploaded = blob_storage.upload_file(local_path=local_path, blob_path=resolved_blob_path, overwrite=True)
    if not uploaded:
        print("Upload failed.")
        return 1

    print(f"Upload completed: {resolved_blob_path}")
    return 0


def download_dataset(local_path: str, category: str, blob_path: str, overwrite: bool) -> int:
    settings, blob_storage = _build_blob_clients()

    if not blob_storage.enabled:
        print("Blob storage is not configured. Download skipped.")
        return 1

    resolved_blob_path = _resolve_blob_path(settings, category, blob_path)
    downloaded = blob_storage.download_file(
        blob_path=resolved_blob_path,
        local_path=local_path,
        overwrite=overwrite,
    )

    if not downloaded:
        print("Download failed.")
        return 1

    print(f"Download completed: {resolved_blob_path} -> {local_path}")
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure dataset sync utility for CyberGuard-ID")
    subparsers = parser.add_subparsers(dest="command", required=True)

    upload_parser = subparsers.add_parser("upload", help="Upload local dataset to Blob storage")
    upload_parser.add_argument("--local-path", required=True, help="Local dataset path")
    upload_parser.add_argument(
        "--category",
        choices=["raw", "processed", "logs"],
        default="raw",
        help="Storage category prefix",
    )
    upload_parser.add_argument(
        "--blob-path",
        default=None,
        help="Relative blob path within selected category. Default: datasets/<filename>",
    )

    download_parser = subparsers.add_parser("download", help="Download dataset from Blob storage")
    download_parser.add_argument("--local-path", required=True, help="Local target path")
    download_parser.add_argument(
        "--category",
        choices=["raw", "processed", "logs"],
        default="raw",
        help="Storage category prefix",
    )
    download_parser.add_argument("--blob-path", required=True, help="Relative blob path within selected category")
    download_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite local file if it already exists",
    )

    sync_parser = subparsers.add_parser("sync-defaults", help="Upload core datasets to Blob storage")
    sync_parser.add_argument(
        "--include-processed",
        action="store_true",
        help="Also upload processed dataset if available",
    )

    return parser


def sync_default_datasets(include_processed: bool) -> int:
    status_codes = []
    status_codes.append(
        upload_dataset(
            local_path="data/external/synthetic_phishing_data.csv",
            category="raw",
            blob_path="datasets/synthetic_phishing_data.csv",
        )
    )

    if include_processed:
        status_codes.append(
            upload_dataset(
                local_path="data/processed/processed_cyber_data.csv",
                category="processed",
                blob_path="datasets/processed_cyber_data.csv",
            )
        )

    return 0 if all(code == 0 for code in status_codes) else 1


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.command == "upload":
        return upload_dataset(local_path=args.local_path, category=args.category, blob_path=args.blob_path)

    if args.command == "download":
        return download_dataset(
            local_path=args.local_path,
            category=args.category,
            blob_path=args.blob_path,
            overwrite=args.overwrite,
        )

    if args.command == "sync-defaults":
        return sync_default_datasets(include_processed=args.include_processed)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
