"""Pydantic request/response models for OSINT Tool REST API."""
from typing import Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target to scan (domain, IP, email, username, phone)")
    modules: list[str] = Field(
        default=["whois", "dns"],
        description="List of modules to run: whois, dns, ip, email, username, ssl, breach, cloud, social"
    )
    output_format: str = Field(default="json", description="Output format: json, html, interactive")
    use_cache: bool = Field(default=True, description="Use cached results if available")
    cache_ttl: int = Field(default=3600, description="Cache TTL in seconds")


class ModuleResult(BaseModel):
    module: str
    target: str
    status: str  # "success", "error", "skipped"
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    cached: bool = False
    duration_ms: int = 0


class ScanResponse(BaseModel):
    target: str
    scan_id: str
    started_at: str
    completed_at: str
    duration_ms: int
    modules_run: list[str]
    results: dict[str, Any]
    report_paths: dict[str, str] = Field(default_factory=dict)


class CacheStatsResponse(BaseModel):
    total_entries: int
    active_entries: int
    expired_entries: int
    total_hits: int
    by_module: dict[str, int] = Field(default_factory=dict)
    db_path: str


class HistoryEntry(BaseModel):
    ts: str
    module: str
    target: str
    status: str


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    module: str | None = None
