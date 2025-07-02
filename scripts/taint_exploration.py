import logging
from collections import defaultdict

from angr.exploration_techniques import ExplorationTechnique
from constants import INPUT_FUNCTION_NAMES, CRITICAL_SINK_FUNCTIONS


class TaintGuidedExploration(ExplorationTechnique):
    """
    Enhanced Angr exploration technique that prioritizes states where tainted data
    has been actively processed. This version integrates with your existing taint analysis
    to guide symbolic execution toward paths that interact with tainted data.
    """

    def __init__(self, logger=None, project=None, max_priority_states=15):
        """
        Initialize the taint-guided exploration technique.

        Args:
            logger: Logger instance for debugging
            project: Angr project instance (to access taint tracking data)
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

        # Initialize reserve stashes if they don't exist
        if "tainted_high_priority" not in simgr.stashes:
            simgr.stashes["tainted_high_priority"] = []
        if "tainted_medium_priority" not in simgr.stashes:
            simgr.stashes["tainted_medium_priority"] = []

        # Get current active states
        states = simgr.stashes[stash]
        
        # Add back states from reserves if we have room
        if len(states) < self.max_priority_states:
            available_slots = self.max_priority_states - len(states)
            
            # First recover high-priority states
            if simgr.stashes["tainted_high_priority"] and available_slots > 0:
                to_recover = min(available_slots, len(simgr.stashes["tainted_high_priority"]))
                recovered = simgr.stashes["tainted_high_priority"][:to_recover]
                simgr.stashes["tainted_high_priority"] = simgr.stashes["tainted_high_priority"][to_recover:]
                states.extend(recovered)
                available_slots -= to_recover
                self.logger.debug(f"Recovered {to_recover} high-priority states")
            
            # Then recover medium-priority states if still have room
            if simgr.stashes["tainted_medium_priority"] and available_slots > 0:
                to_recover = min(available_slots, len(simgr.stashes["tainted_medium_priority"]))
                recovered = simgr.stashes["tainted_medium_priority"][:to_recover]
                simgr.stashes["tainted_medium_priority"] = simgr.stashes["tainted_medium_priority"][to_recover:]
                states.extend(recovered)
                self.logger.debug(f"Recovered {to_recover} medium-priority states")

        # Score and classify all states (active + recovered)
        scored_states = []
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

        # Manage state overflow using the parameter
        if len(prioritized_states) > self.max_priority_states:
            # Keep the top states active
            active_states = prioritized_states[:self.max_priority_states]
            overflow_states = prioritized_states[self.max_priority_states:]
            
            simgr.stashes[stash] = active_states
            
            # Store overflow states in appropriate reserves
            for state in overflow_states:
                score = self._calculate_taint_score(state)
                if score >= 6.0:
                    simgr.stashes["tainted_high_priority"].append(state)
                else:
                    simgr.stashes["tainted_medium_priority"].append(state)
            
            self.logger.debug(f"Moved {len(overflow_states)} states to reserves")
        else:
            # All states fit in active exploration
            simgr.stashes[stash] = prioritized_states

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
            if depth > 400:
                score *= 0.9
            elif depth > 200:
                score *= 0.95

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
        # Function-level metrics (what humans care about)
        total_functions = len(self.project.kb.functions) if self.project else 0
        tainted_functions_count = (
            len(self.project.tainted_functions) if self.project else 0
        )
        tainted_edges_count = len(self.project.tainted_edges) if self.project else 0

        # Input source analysis
        input_sources = [
            f
            for f in (self.project.tainted_functions or [])
            if f in INPUT_FUNCTION_NAMES
        ]

        # Critical sink analysis (potential vulnerability points)
        critical_sinks = [
            f
            for f in (self.project.tainted_functions or [])
            if f in CRITICAL_SINK_FUNCTIONS
        ]

        return {
            "total_functions": total_functions,
            "tainted_functions_count": tainted_functions_count,
            "taint_propagation_paths": tainted_edges_count,
            "input_sources_found": len(input_sources),
            "input_source_names": input_sources,
            "critical_sinks_found": len(critical_sinks),
            "critical_sink_names": critical_sinks,
        }
