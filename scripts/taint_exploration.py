import logging
import time
from collections import defaultdict

from angr.exploration_techniques import ExplorationTechnique
from constants import INPUT_FUNCTION_NAMES


class TaintGuidedExploration(ExplorationTechnique):
    """
    Enhanced Angr exploration technique that prioritizes states where tainted data
    has been actively processed. This version integrates with your existing taint analysis
    to guide symbolic execution toward paths that interact with tainted data.
    """

    def __init__(self, logger=None, project=None, max_priority_states=20):
        """
        Initialize the taint-guided exploration technique.

        Args:
            logger: Logger instance for debugging
            project: Angr project instance (to access taint tracking data)
            priority_weight (float): Multiplier for tainted state priorities
            max_priority_states (int): Maximum number of high-priority states to maintain
        """
        super().__init__()
        self.logger = logger or logging.getLogger(__name__)
        self.project = project
        self.max_priority_states = max_priority_states

        # Metrics and tracking
        self.tainted_states_explored = 0
        self.untainted_states_explored = 0
        self.state_taint_history = defaultdict(list)
        self.exploration_start_time = time.time()

        # State management
        self.state_scores = {}

    def step(self, simgr, stash="active", **kwargs):
        """
        Enhanced step function that classifies, scores, and reorders states
        before symbolic execution.
        """
        self._classify_and_prioritize_states(simgr, stash)

        simgr = simgr.step(stash=stash, **kwargs)

        self._update_metrics(simgr)

        return simgr

    def _classify_and_prioritize_states(self, simgr, stash):
        """
        Classify states based on taint information and reorder the exploration queue.
        """
        if stash not in simgr.stashes or not simgr.stashes[stash]:
            return

        states = simgr.stashes[stash]
        scored_states = []

        # Score each state based on taint relevance
        for state in states:
            score = self._calculate_taint_score(state)
            scored_states.append((score, state))
            self.state_scores[id(state)] = score
            self.state_taint_history[id(state)].append(score)

        # Sort states by taint score (higher scores = higher priority)
        scored_states.sort(key=lambda x: x[0], reverse=True)

        high_priority = []
        medium_priority = []
        normal_priority = []

        for score, state in scored_states:
            if score >= 6.0:
                high_priority.append(state)
            elif score >= 2.0:
                medium_priority.append(state)
            else:
                normal_priority.append(state)

        prioritized_states = high_priority + medium_priority + normal_priority
        simgr.stashes[stash] = prioritized_states

        if len(prioritized_states) > 15:
            simgr.stashes[stash] = prioritized_states[:15]
            simgr.stashes["tainted_high_priority"].extend(
                high_priority[5:] if len(high_priority) > 5 else []
            )
            simgr.stashes["tainted_medium_priority"].extend(prioritized_states[15:])

    def _calculate_taint_score(self, state):
        """
        Calculate a taint relevance score for a given state.
        Relies primarily on taint_score maintained by hooks in taint_se.py.
        """
        try:
            # Primary score from hooks that detect taint in real-time
            base_score = state.globals.get("taint_score", 0)

            # Minimum exploration score so states don't get stuck
            score = max(base_score, 1.0)

            # Bonus for being in a known tainted function
            current_func = self._get_current_function_name(state)
            if (
                current_func
                and self.project
                and hasattr(self.project, "tainted_functions")
                and current_func in self.project.tainted_functions
            ):
                score += 3.0

            # Bonus for main function and entry points (exploration priority)
            if current_func and (
                "main" in current_func.lower()
                or state.addr == getattr(self.project, "entry", 0)
            ):
                score += 1.5

            # Small penalty for excessive depth to avoid infinite loops
            depth = len(state.history.bbl_addrs) if state.history.bbl_addrs else 0
            if depth > 200:
                score *= 0.95
            elif depth > 400:
                score *= 0.9

            # Bonus for potential to discover new tainted functions
            if (
                current_func
                and self.project
                and hasattr(self.project, "tainted_functions")
                and current_func not in self.project.tainted_functions
            ):
                score += 1.0  # Moderate bonus for exploration

            return max(score, 1.0)

        except Exception as e:
            self.logger.warning(f"Error calculating taint score: {e}")
            return 1.0

    def _get_current_function_name(self, state):
        """Get the name of the current function."""
        try:
            if (
                self.project
                and hasattr(self.project, "kb")
                and self.project.kb.functions
            ):
                func = self.project.kb.functions.get_by_addr(state.addr)
                if func and func.name:
                    return func.name
            return f"sub_{state.addr:#x}"
        except Exception:
            return f"sub_{state.addr:#x}"

    def _update_metrics(self, simgr):
        """Update exploration metrics."""
        for state in simgr.deadended + simgr.stashes.get("found", []):
            state_id = id(state)
            if state_id in self.state_scores:
                if self.state_scores[state_id] >= 4.0:
                    self.tainted_states_explored += 1
                else:
                    self.untainted_states_explored += 1

    def get_exploration_metrics(self):
        """Get meaningful analysis metrics for human interpretation."""
        elapsed_time = time.time() - self.exploration_start_time
        
        # Function-level metrics (what humans care about)
        total_functions = len(self.project.kb.functions) if self.project else 0
        tainted_functions_count = len(self.project.tainted_functions) if self.project else 0
        tainted_edges_count = len(self.project.tainted_edges) if self.project else 0
        
        # Input source analysis
        input_sources = [f for f in (self.project.tainted_functions or []) 
                        if f in INPUT_FUNCTION_NAMES]
        
        # Critical sink analysis (potential vulnerability points)
        critical_sinks = [f for f in (self.project.tainted_functions or []) 
                         if f in {"printf", "sprintf", "strcpy", "strcat", "system"}]

        return {
            "elapsed_time": elapsed_time,
            "total_functions": total_functions,
            "tainted_functions_count": tainted_functions_count,
            "tainted_function_ratio": tainted_functions_count / max(total_functions, 1),
            "taint_propagation_paths": tainted_edges_count,
            "input_sources_found": len(input_sources),
            "input_source_names": input_sources,
            "critical_sinks_found": len(critical_sinks),
            "critical_sink_names": critical_sinks,
        }

    def print_metrics(self):
        """Print human-meaningful analysis results."""
        metrics = self.get_exploration_metrics()

        self.logger.info("=" * 60)
        self.logger.info("TAINT ANALYSIS RESULTS")
        self.logger.info("=" * 60)
        self.logger.info(f"Analysis Time: {metrics['elapsed_time']:.2f}s")
        self.logger.info(f"Functions Analyzed: {metrics['total_functions']} total")
        self.logger.info(f"Tainted Functions: {metrics['tainted_functions_count']} ({metrics['tainted_function_ratio']:.1%})")
        self.logger.info(f"Taint Propagation Paths: {metrics['taint_propagation_paths']}")
        
        # Input sources
        if metrics['input_sources_found'] > 0:
            sources_str = ", ".join(metrics['input_source_names'])
            self.logger.info(f"Input Sources: {metrics['input_sources_found']} ({sources_str})")
        else:
            self.logger.info("Input Sources: None detected")
        
        # Security-relevant sinks
        if metrics['critical_sinks_found'] > 0:
            sinks_str = ", ".join(metrics['critical_sink_names'])
            self.logger.info(f"Critical Sinks: {metrics['critical_sinks_found']} ({sinks_str})")
            self.logger.info("Review these functions for potential vulnerabilities")
        else:
            self.logger.info("Critical Sinks: None detected")
        
        self.logger.info("=" * 60)
        
        # Analysis quality assessment
        if metrics['tainted_function_ratio'] > 0.3:
            self.logger.info("High taint coverage: Comprehensive input processing detected")
        elif metrics['tainted_function_ratio'] > 0.1:
            self.logger.info("Moderate taint coverage: Some input processing detected")
        else:
            self.logger.info("Low taint coverage: Limited input processing or detection issues")
