from dataclasses import dataclass


@dataclass
class ServerConfig:
    host: str = "localhost"
    port: int = 9009
    debug: bool = False


@dataclass
class BinaryNinjaConfig:
    api_version: str | None = None
    log_level: str = "INFO"
    # GUI views have an application-owned lifetime. Headless hosts override
    # this with a finite limit so background analysis databases cannot
    # accumulate indefinitely across MCP clients.
    max_owned_views: int | None = None
    max_rss_mb: int | None = None


class Config:
    def __init__(self):
        self.server = ServerConfig()
        self.binary_ninja = BinaryNinjaConfig()
