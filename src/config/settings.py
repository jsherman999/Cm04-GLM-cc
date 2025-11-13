"""
Configuration settings for CM-04 Scanner application
"""

from typing import List, Optional
from pydantic import BaseSettings, Field
from pathlib import Path


class Settings(BaseSettings):
    """Application configuration settings"""

    # Application settings
    app_name: str = Field(default="CM-04 Scanner", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")

    # Server settings
    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT")

    # SSH settings
    ssh_timeout: int = Field(default=30, env="SSH_TIMEOUT")
    ssh_concurrency_limit: int = Field(default=100, env="SSH_CONCURRENCY_LIMIT")
    ssh_key_file: Optional[Path] = Field(default=None, env="SSH_KEY_FILE")
    ssh_user: Optional[str] = Field(default=None, env="SSH_USER")

    # Database settings
    database_url: str = Field(default="sqlite+aiosqlite:///./cm04_scanner.db", env="DATABASE_URL")

    # Redis settings for caching and job queue
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")

    # Security settings
    secret_key: str = Field(default="change-me-in-production", env="SECRET_KEY")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")

    # File upload settings
    max_file_size: int = Field(default=10 * 1024 * 1024, env="MAX_FILE_SIZE")  # 10MB
    upload_dir: Path = Field(default=Path("./uploads"), env="UPLOAD_DIR")
    reports_dir: Path = Field(default=Path("./reports"), env="REPORTS_DIR")

    # Job settings
    job_timeout: int = Field(default=3600, env="JOB_TIMEOUT")  # 1 hour
    max_concurrent_jobs: int = Field(default=10, env="MAX_CONCURRENT_JOBS")

    # QAS/VAS settings
    vastool_path: str = Field(default="/opt/quest/bin/vastool", env="VASTOOL_PATH")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()