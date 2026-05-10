"""
Genetic Profile Engine Module - Genetic algorithm-driven Profile auto-evolution.

This module provides genetic algorithm capabilities for automatically evolving
Malleable C2 Profiles based on fitness functions including camouflage similarity,
survival time, and data transmission success rate.

Core capabilities:
    1. Genetic algorithm for Profile mutation and crossover
    2. Fitness evaluation based on camouflage, survival, and success rate
    3. Automatic promotion of high-fitness Profiles
    4.淘汰 low-fitness Profiles
    5. Profile gene pool management
    6. Evolution history tracking

Author: Kunlun Security Lab
License: Internal Use Only
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Enums
# =============================================================================

class ProfileGeneType(str, Enum):
    """Types of Profile genes."""

    HTTP_HEADER = "http_header"
    URI_PATH = "uri_path"
    HTTP_METHOD = "http_method"
    USER_AGENT = "user_agent"
    JITTER = "jitter"
    SLEEP_INTERVAL = "sleep_interval"
    DATA_TRANSFORM = "data_transform"
    HOST_HEADER = "host_header"
    PARAMETER = "parameter"
    RESPONSE_MIMIC = "response_mimic"


class EvolutionPhase(str, Enum):
    """Evolution phases."""

    INITIALIZATION = "initialization"
    SELECTION = "selection"
    CROSSOVER = "crossover"
    MUTATION = "mutation"
    EVALUATION = "evaluation"
    REPLACEMENT = "replacement"
    CONVERGED = "converged"


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ProfileGene:
    """A single gene in a Profile chromosome.

    Attributes:
        gene_type: Type of gene
        value: Gene value
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        mutation_rate: Probability of mutation
    """

    gene_type: ProfileGeneType = ProfileGeneType.HTTP_HEADER
    value: Any = None
    min_value: Any = None
    max_value: Any = None
    mutation_rate: float = 0.1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "gene_type": self.gene_type.value,
            "value": str(self.value)[:50],
        }

    def mutate(self) -> "ProfileGene":
        """Mutate this gene.

        Returns:
            Mutated gene.
        """
        if random.random() > self.mutation_rate:
            return self

        new_gene = copy.deepcopy(self)

        if isinstance(self.value, (int, float)):
            if self.min_value is not None and self.max_value is not None:
                new_gene.value = random.uniform(
                    float(self.min_value), float(self.max_value),
                )
            else:
                new_gene.value = self.value * random.uniform(0.5, 1.5)
        elif isinstance(self.value, str):
            new_gene.value = self._mutate_string(self.value)
        elif isinstance(self.value, list):
            if self.value:
                idx = random.randint(0, len(self.value) - 1)
                new_gene.value[idx] = self._mutate_string(str(self.value[idx]))

        return new_gene

    def _mutate_string(self, value: str) -> str:
        """Mutate a string value.

        Args:
            value: Original string.

        Returns:
            Mutated string.
        """
        mutations = [
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s + str(random.randint(0, 9)),
            lambda s: s[:-1] if len(s) > 1 else s,
            lambda s: s.replace("http", "https") if "http" in s else s,
        ]

        return random.choice(mutations)(value)


@dataclass
class ProfileChromosome:
    """A complete Profile chromosome (set of genes).

    Attributes:
        profile_id: Unique profile identifier
        genes: List of genes
        fitness_score: Overall fitness score
        generation: Generation number
        survival_time: Time survived in seconds
        success_rate: Task success rate
        detection_count: Number of detections
        created_at: Creation timestamp
    """

    profile_id: str = ""
    genes: List[ProfileGene] = field(default_factory=list)
    fitness_score: float = 0.0
    generation: int = 0
    survival_time: float = 0.0
    success_rate: float = 0.0
    detection_count: int = 0
    created_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "profile_id": self.profile_id,
            "fitness_score": self.fitness_score,
            "generation": self.generation,
            "gene_count": len(self.genes),
            "survival_time": self.survival_time,
            "success_rate": self.success_rate,
            "detection_count": self.detection_count,
        }

    def to_profile_config(self) -> Dict[str, Any]:
        """Convert chromosome to Profile configuration.

        Returns:
            Dictionary with Profile configuration.
        """
        config: Dict[str, Any] = {}

        for gene in self.genes:
            if gene.gene_type == ProfileGeneType.HTTP_HEADER:
                config["http_headers"] = gene.value
            elif gene.gene_type == ProfileGeneType.URI_PATH:
                config["uri_paths"] = gene.value
            elif gene.gene_type == ProfileGeneType.HTTP_METHOD:
                config["http_method"] = gene.value
            elif gene.gene_type == ProfileGeneType.USER_AGENT:
                config["user_agent"] = gene.value
            elif gene.gene_type == ProfileGeneType.JITTER:
                config["jitter"] = gene.value
            elif gene.gene_type == ProfileGeneType.SLEEP_INTERVAL:
                config["sleep_interval"] = gene.value
            elif gene.gene_type == ProfileGeneType.DATA_TRANSFORM:
                config["data_transform"] = gene.value
            elif gene.gene_type == ProfileGeneType.HOST_HEADER:
                config["host_header"] = gene.value
            elif gene.gene_type == ProfileGeneType.PARAMETER:
                config["parameters"] = gene.value
            elif gene.gene_type == ProfileGeneType.RESPONSE_MIMIC:
                config["response_mimic"] = gene.value

        return config


@dataclass
class EvolutionConfig:
    """Genetic algorithm configuration.

    Attributes:
        population_size: Number of individuals per generation
        crossover_rate: Probability of crossover
        mutation_rate: Base mutation probability
        elitism_count: Number of elite individuals preserved
        max_generations: Maximum generations
        fitness_weights: Weights for fitness components
        convergence_threshold: Convergence threshold
    """

    population_size: int = 50
    crossover_rate: float = 0.8
    mutation_rate: float = 0.1
    elitism_count: int = 5
    max_generations: int = 100
    fitness_weights: Dict[str, float] = field(default_factory=lambda: {
        "camouflage": 0.4,
        "survival": 0.3,
        "success_rate": 0.2,
        "stealth": 0.1,
    })
    convergence_threshold: float = 0.01

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "population_size": self.population_size,
            "crossover_rate": self.crossover_rate,
            "mutation_rate": self.mutation_rate,
            "elitism_count": self.elitism_count,
            "max_generations": self.max_generations,
        }


@dataclass
class EvolutionReport:
    """Evolution generation report.

    Attributes:
        generation: Generation number
        phase: Current evolution phase
        best_fitness: Best fitness score
        avg_fitness: Average fitness score
        worst_fitness: Worst fitness score
        diversity: Population diversity
        profiles_evaluated: Number of profiles evaluated
        elapsed_seconds: Time elapsed
    """

    generation: int = 0
    phase: EvolutionPhase = EvolutionPhase.INITIALIZATION
    best_fitness: float = 0.0
    avg_fitness: float = 0.0
    worst_fitness: float = 0.0
    diversity: float = 0.0
    profiles_evaluated: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "generation": self.generation,
            "phase": self.phase.value,
            "best_fitness": self.best_fitness,
            "avg_fitness": self.avg_fitness,
            "worst_fitness": self.worst_fitness,
            "diversity": self.diversity,
            "profiles_evaluated": self.profiles_evaluated,
        }


# =============================================================================
# Fitness Evaluator
# =============================================================================

class FitnessEvaluator:
    """Evaluates fitness of Profile chromosomes.

    Uses multiple criteria: camouflage similarity, survival time,
    task success rate, and stealth metrics.

    Attributes:
        _weights: Fitness component weights
    """

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        """Initialize the FitnessEvaluator.

        Args:
            weights: Fitness component weights.
        """
        self._weights = weights or {
            "camouflage": 0.4,
            "survival": 0.3,
            "success_rate": 0.2,
            "stealth": 0.1,
        }

    def evaluate(
        self,
        chromosome: ProfileChromosome,
        reference_traffic: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Evaluate fitness of a chromosome.

        Args:
            chromosome: Profile chromosome.
            reference_traffic: Reference traffic for comparison.

        Returns:
            Fitness score (0-1).
        """
        camouflage_score = self._evaluate_camouflage(
            chromosome, reference_traffic,
        )
        survival_score = self._evaluate_survival(chromosome)
        success_score = self._evaluate_success_rate(chromosome)
        stealth_score = self._evaluate_stealth(chromosome)

        fitness = (
            self._weights.get("camouflage", 0.4) * camouflage_score +
            self._weights.get("survival", 0.3) * survival_score +
            self._weights.get("success_rate", 0.2) * success_score +
            self._weights.get("stealth", 0.1) * stealth_score
        )

        chromosome.fitness_score = fitness
        return fitness

    def _evaluate_camouflage(
        self,
        chromosome: ProfileChromosome,
        reference_traffic: Optional[Dict[str, Any]],
    ) -> float:
        """Evaluate camouflage similarity.

        Args:
            chromosome: Profile chromosome.
            reference_traffic: Reference traffic.

        Returns:
            Camouflage score (0-1).
        """
        if not reference_traffic:
            return 0.5

        profile_config = chromosome.to_profile_config()
        similarity_scores: List[float] = []

        ref_headers = reference_traffic.get("headers", {})
        prof_headers = profile_config.get("http_headers", {})

        if ref_headers and prof_headers:
            common_keys = set(ref_headers.keys()) & set(prof_headers.keys())
            if common_keys:
                header_similarity = len(common_keys) / len(ref_headers)
                similarity_scores.append(header_similarity)

        ref_ua = reference_traffic.get("user_agent", "")
        prof_ua = profile_config.get("user_agent", "")

        if ref_ua and prof_ua:
            ua_similarity = self._string_similarity(ref_ua, prof_ua)
            similarity_scores.append(ua_similarity)

        if similarity_scores:
            return sum(similarity_scores) / len(similarity_scores)

        return 0.5

    def _evaluate_survival(self, chromosome: ProfileChromosome) -> float:
        """Evaluate survival time.

        Args:
            chromosome: Profile chromosome.

        Returns:
            Survival score (0-1).
        """
        max_survival = 86400 * 30
        return min(chromosome.survival_time / max_survival, 1.0)

    def _evaluate_success_rate(self, chromosome: ProfileChromosome) -> float:
        """Evaluate task success rate.

        Args:
            chromosome: Profile chromosome.

        Returns:
            Success rate score (0-1).
        """
        return chromosome.success_rate

    def _evaluate_stealth(self, chromosome: ProfileChromosome) -> float:
        """Evaluate stealth (inverse of detection count).

        Args:
            chromosome: Profile chromosome.

        Returns:
            Stealth score (0-1).
        """
        if chromosome.detection_count == 0:
            return 1.0

        return max(0.0, 1.0 - (chromosome.detection_count * 0.1))

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Calculate string similarity.

        Args:
            s1: First string.
            s2: Second string.

        Returns:
            Similarity score (0-1).
        """
        if not s1 or not s2:
            return 0.0

        set1 = set(s1.lower())
        set2 = set(s2.lower())

        intersection = set1 & set2
        union = set1 | set2

        if not union:
            return 0.0

        return len(intersection) / len(union)


# =============================================================================
# Genetic Operators
# =============================================================================

class GeneticOperators:
    """Genetic algorithm operators for Profile evolution.

    Implements selection, crossover, and mutation operations
    specific to Profile chromosomes.

    Attributes:
        _crossover_rate: Crossover probability
        _mutation_rate: Mutation probability
    """

    def __init__(
        self,
        crossover_rate: float = 0.8,
        mutation_rate: float = 0.1,
    ) -> None:
        """Initialize the GeneticOperators.

        Args:
            crossover_rate: Crossover probability.
            mutation_rate: Mutation probability.
        """
        self._crossover_rate = crossover_rate
        self._mutation_rate = mutation_rate

    def tournament_selection(
        self,
        population: List[ProfileChromosome],
        tournament_size: int = 5,
    ) -> ProfileChromosome:
        """Select individual via tournament selection.

        Args:
            population: Population of chromosomes.
            tournament_size: Tournament size.

        Returns:
            Selected chromosome.
        """
        tournament = random.sample(
            population, min(tournament_size, len(population)),
        )
        return max(tournament, key=lambda c: c.fitness_score)

    def crossover(
        self,
        parent1: ProfileChromosome,
        parent2: ProfileChromosome,
    ) -> Tuple[ProfileChromosome, ProfileChromosome]:
        """Perform crossover between two parents.

        Args:
            parent1: First parent.
            parent2: Second parent.

        Returns:
            Tuple of two child chromosomes.
        """
        if random.random() > self._crossover_rate:
            return copy.deepcopy(parent1), copy.deepcopy(parent2)

        child1 = copy.deepcopy(parent1)
        child2 = copy.deepcopy(parent2)

        crossover_point = random.randint(1, len(child1.genes) - 1)

        child1.genes[crossover_point:] = copy.deepcopy(
            parent2.genes[crossover_point:],
        )
        child2.genes[crossover_point:] = copy.deepcopy(
            parent1.genes[crossover_point:],
        )

        return child1, child2

    def mutate(self, chromosome: ProfileChromosome) -> ProfileChromosome:
        """Mutate a chromosome.

        Args:
            chromosome: Chromosome to mutate.

        Returns:
            Mutated chromosome.
        """
        mutated = copy.deepcopy(chromosome)

        for i, gene in enumerate(mutated.genes):
            gene.mutation_rate = self._mutation_rate
            mutated.genes[i] = gene.mutate()

        return mutated


# =============================================================================
# Profile Gene Pool
# =============================================================================

class ProfileGenePool:
    """Pool of Profile genes for evolution.

    Maintains a diverse set of genes that can be combined
    to create new Profile chromosomes.

    Attributes:
        _genes: Dictionary of genes by type
        _usage_count: Gene usage tracking
    """

    DEFAULT_GENES: Dict[ProfileGeneType, List[Any]] = {
        ProfileGeneType.HTTP_HEADER: [
            {"Content-Type": "application/json"},
            {"Content-Type": "application/octet-stream"},
            {"Content-Type": "text/html"},
            {"Accept": "text/html,application/xhtml+xml"},
            {"Accept-Encoding": "gzip, deflate, br"},
        ],
        ProfileGeneType.URI_PATH: [
            ["/api/v1/users", "/api/v1/settings", "/api/v1/profile"],
            ["/cdn/assets/js", "/cdn/assets/css", "/cdn/assets/img"],
            ["/static/images", "/static/scripts", "/static/styles"],
            ["/graphql", "/api/rest", "/api/v2/data"],
        ],
        ProfileGeneType.HTTP_METHOD: ["GET", "POST", "PUT", "PATCH"],
        ProfileGeneType.USER_AGENT: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
        ],
        ProfileGeneType.JITTER: [0.3, 0.4, 0.5, 0.6, 0.7],
        ProfileGeneType.SLEEP_INTERVAL: [30, 60, 120, 300, 600],
        ProfileGeneType.DATA_TRANSFORM: ["base64", "netbios", "mask"],
        ProfileGeneType.HOST_HEADER: [
            "ajax.googleapis.com",
            "cdn.jsdelivr.net",
            "fonts.googleapis.com",
            "api.microsoft.com",
        ],
        ProfileGeneType.PARAMETER: [
            {"token": "random", "version": "1.0"},
            {"session": "random", "locale": "en-US"},
            {"id": "random", "format": "json"},
        ],
        ProfileGeneType.RESPONSE_MIMIC: [
            {"server": "nginx", "x-powered-by": "Express"},
            {"server": "Apache", "x-powered-by": "PHP/8.0"},
            {"server": "cloudflare", "cf-ray": "random"},
        ],
    }

    def __init__(self) -> None:
        """Initialize the ProfileGenePool."""
        self._genes: Dict[ProfileGeneType, List[Any]] = copy.deepcopy(
            self.DEFAULT_GENES,
        )
        self._usage_count: Dict[str, int] = {}

    def get_random_genes(self) -> List[ProfileGene]:
        """Get random set of genes for a new chromosome.

        Returns:
            List of ProfileGene.
        """
        genes: List[ProfileGene] = []

        for gene_type, values in self._genes.items():
            if values:
                value = random.choice(values)
                genes.append(ProfileGene(
                    gene_type=gene_type,
                    value=copy.deepcopy(value),
                ))

        return genes

    def add_gene(self, gene_type: ProfileGeneType, value: Any) -> None:
        """Add a new gene to the pool.

        Args:
            gene_type: Gene type.
            value: Gene value.
        """
        if gene_type not in self._genes:
            self._genes[gene_type] = []

        self._genes[gene_type].append(value)

    def get_gene_usage(self) -> Dict[str, int]:
        """Get gene usage statistics.

        Returns:
            Dictionary of gene usage counts.
        """
        return self._usage_count

    def get_status(self) -> Dict[str, Any]:
        """Get gene pool status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "gene_types": len(self._genes),
            "total_genes": sum(len(v) for v in self._genes.values()),
            "usage_count": self._usage_count,
        }


# =============================================================================
# Genetic Profile Engine
# =============================================================================

class GeneticProfileEngine:
    """Main genetic algorithm Profile evolution engine.

    Coordinates the entire evolution process including
    initialization, selection, crossover, mutation, and
    evaluation of Profile chromosomes.

    Attributes:
        _config: Evolution configuration
        _gene_pool: Profile gene pool
        _fitness_evaluator: Fitness evaluator
        _genetic_ops: Genetic operators
        _population: Current population
        _generation: Current generation number
        _best_chromosome: Best chromosome found
        _evolution_history: History of evolution reports
    """

    def __init__(
        self,
        config: Optional[EvolutionConfig] = None,
    ) -> None:
        """Initialize the GeneticProfileEngine.

        Args:
            config: Evolution configuration.
        """
        self._config = config or EvolutionConfig()
        self._gene_pool = ProfileGenePool()
        self._fitness_evaluator = FitnessEvaluator(
            self._config.fitness_weights,
        )
        self._genetic_ops = GeneticOperators(
            self._config.crossover_rate,
            self._config.mutation_rate,
        )
        self._population: List[ProfileChromosome] = []
        self._generation = 0
        self._best_chromosome: Optional[ProfileChromosome] = None
        self._evolution_history: List[EvolutionReport] = []

    async def evolve(
        self,
        reference_traffic: Optional[Dict[str, Any]] = None,
        generations: Optional[int] = None,
    ) -> ProfileChromosome:
        """Run evolution process.

        Args:
            reference_traffic: Reference traffic for fitness.
            generations: Number of generations (uses config if None).

        Returns:
            Best ProfileChromosome found.
        """
        max_gen = generations or self._config.max_generations

        if not self._population:
            await self._initialize_population()

        for gen in range(max_gen):
            self._generation = gen + 1

            report = await self._evolve_generation(reference_traffic)
            self._evolution_history.append(report)

            logger.info(
                f"Generation {self._generation}: "
                f"best={report.best_fitness:.4f}, "
                f"avg={report.avg_fitness:.4f}, "
                f"diversity={report.diversity:.4f}"
            )

            if report.diversity < self._config.convergence_threshold:
                logger.info("Population converged, stopping evolution")
                break

        return self._best_chromosome or self._population[0]

    async def _initialize_population(self) -> None:
        """Initialize population with random chromosomes."""
        self._population = []

        for i in range(self._config.population_size):
            genes = self._gene_pool.get_random_genes()
            chromosome = ProfileChromosome(
                profile_id=hashlib.md5(
                    f"profile_{i}_{time.time()}".encode()
                ).hexdigest()[:12],
                genes=genes,
                generation=0,
                created_at=time.time(),
            )
            self._population.append(chromosome)

        logger.info(
            f"Population initialized: {len(self._population)} individuals"
        )

    async def _evolve_generation(
        self,
        reference_traffic: Optional[Dict[str, Any]],
    ) -> EvolutionReport:
        """Evolve one generation.

        Args:
            reference_traffic: Reference traffic.

        Returns:
            EvolutionReport for this generation.
        """
        start_time = time.time()

        self._evaluate_population(reference_traffic)

        best = max(self._population, key=lambda c: c.fitness_score)
        if (
            not self._best_chromosome
            or best.fitness_score > self._best_chromosome.fitness_score
        ):
            self._best_chromosome = copy.deepcopy(best)

        new_population = self._select_elites()

        while len(new_population) < self._config.population_size:
            parent1 = self._genetic_ops.tournament_selection(self._population)
            parent2 = self._genetic_ops.tournament_selection(self._population)

            child1, child2 = self._genetic_ops.crossover(parent1, parent2)

            child1 = self._genetic_ops.mutate(child1)
            child2 = self._genetic_ops.mutate(child2)

            child1.generation = self._generation
            child2.generation = self._generation

            new_population.extend([child1, child2])

        self._population = new_population[:self._config.population_size]

        elapsed = time.time() - start_time

        fitness_scores = [c.fitness_score for c in self._population]
        diversity = self._calculate_diversity()

        return EvolutionReport(
            generation=self._generation,
            phase=EvolutionPhase.EVALUATION,
            best_fitness=best.fitness_score,
            avg_fitness=sum(fitness_scores) / len(fitness_scores),
            worst_fitness=min(fitness_scores),
            diversity=diversity,
            profiles_evaluated=len(self._population),
            elapsed_seconds=elapsed,
        )

    def _evaluate_population(
        self, reference_traffic: Optional[Dict[str, Any]],
    ) -> None:
        """Evaluate fitness of entire population.

        Args:
            reference_traffic: Reference traffic.
        """
        for chromosome in self._population:
            self._fitness_evaluator.evaluate(chromosome, reference_traffic)

    def _select_elites(self) -> List[ProfileChromosome]:
        """Select elite individuals for next generation.

        Returns:
            List of elite chromosomes.
        """
        sorted_pop = sorted(
            self._population, key=lambda c: c.fitness_score, reverse=True,
        )
        return copy.deepcopy(sorted_pop[:self._config.elitism_count])

    def _calculate_diversity(self) -> float:
        """Calculate population diversity.

        Returns:
            Diversity score (0-1).
        """
        if len(self._population) < 2:
            return 0.0

        fitness_scores = [c.fitness_score for c in self._population]
        mean = sum(fitness_scores) / len(fitness_scores)
        variance = sum((s - mean) ** 2 for s in fitness_scores) / len(fitness_scores)
        std_dev = math.sqrt(variance)

        return min(std_dev * 2, 1.0)

    def get_best_profile(self) -> Optional[Dict[str, Any]]:
        """Get best Profile configuration found.

        Returns:
            Best Profile configuration, or None.
        """
        if not self._best_chromosome:
            return None

        return self._best_chromosome.to_profile_config()

    def get_evolution_history(self) -> List[Dict[str, Any]]:
        """Get evolution history.

        Returns:
            List of evolution report dictionaries.
        """
        return [r.to_dict() for r in self._evolution_history]

    def get_status(self) -> Dict[str, Any]:
        """Get engine status.

        Returns:
            Dictionary with status summary.
        """
        return {
            "generation": self._generation,
            "population_size": len(self._population),
            "best_fitness": (
                self._best_chromosome.fitness_score
                if self._best_chromosome else 0.0
            ),
            "gene_pool": self._gene_pool.get_status(),
            "evolution_reports": len(self._evolution_history),
        }


# =============================================================================
# Global Singleton
# =============================================================================

_genetic_engine: Optional[GeneticProfileEngine] = None


def get_genetic_profile_engine(
    config: Optional[EvolutionConfig] = None,
) -> GeneticProfileEngine:
    """Get the global GeneticProfileEngine singleton.

    Args:
        config: Evolution configuration.

    Returns:
        Singleton GeneticProfileEngine instance.
    """
    global _genetic_engine
    if _genetic_engine is None:
        _genetic_engine = GeneticProfileEngine(config)
    return _genetic_engine


__all__ = [
    "GeneticProfileEngine",
    "FitnessEvaluator",
    "GeneticOperators",
    "ProfileGenePool",
    "ProfileChromosome",
    "ProfileGene",
    "EvolutionConfig",
    "EvolutionReport",
    "ProfileGeneType",
    "EvolutionPhase",
    "get_genetic_profile_engine",
]
