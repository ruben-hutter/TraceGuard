from angr.exploration_techniques import ExplorationTechnique
import logging
from collections import defaultdict, deque
import time


class TaintGuidedExploration(ExplorationTechnique):
    """
    Enhanced Angr exploration technique that prioritizes states where tainted data
    has been actively processed. This version integrates with your existing taint analysis
    to guide symbolic execution toward paths that interact with tainted data.
    """
    
    def __init__(self, logger=None, project=None, priority_weight=5.0, max_priority_states=20):
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
        self.priority_weight = priority_weight
        self.max_priority_states = max_priority_states
        
        # Metrics and tracking
        self.tainted_states_explored = 0
        self.untainted_states_explored = 0
        self.state_taint_history = defaultdict(list)
        self.exploration_start_time = time.time()
        
        # State management
        self.high_priority_queue = deque(maxlen=max_priority_states)
        self.state_scores = {}
        
        if self.logger:
            self.logger.info("Enhanced TaintGuidedExploration initialized")
    
    def setup(self, simgr):
        """Setup custom stashes for managing tainted states."""
        simgr.stashes['tainted_high_priority'] = []
        simgr.stashes['tainted_medium_priority'] = []
        simgr.stashes['low_priority'] = []
        
        if self.logger:
            self.logger.debug("TaintGuidedExploration stashes initialized")
    
    def step(self, simgr, stash='active', **kwargs):
        """
        Enhanced step function that classifies, scores, and reorders states
        before symbolic execution.
        """
        # Classify and prioritize states before stepping
        self._classify_and_prioritize_states(simgr, stash)
        
        # Execute the original step
        simgr = simgr.step(stash=stash, **kwargs)
        
        # Post-step processing
        self._post_step_processing(simgr)
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
            score = self._calculate_comprehensive_taint_score(state)
            scored_states.append((score, state))
            self.state_scores[id(state)] = score
            self.state_taint_history[id(state)].append(score)
        
        # Sort states by taint score (higher scores = higher priority)
        scored_states.sort(key=lambda x: x[0], reverse=True)
        
        # FIXED: More lenient thresholds and ensure states stay explorable
        high_priority = []
        medium_priority = []
        normal_priority = []
        
        for score, state in scored_states:
            if score >= 6.0:  # Very high taint relevance
                high_priority.append(state)
            elif score >= 2.0:  # Medium taint relevance  
                medium_priority.append(state)
            else:
                normal_priority.append(state)  # Keep all other states explorable
        
        # FIXED: Always keep states in active stash for exploration
        # Reorder by priority but don't move to separate stashes initially
        prioritized_states = high_priority + medium_priority + normal_priority
        simgr.stashes[stash] = prioritized_states
        
        # Only move excess states to other stashes if we have too many
        if len(prioritized_states) > 15:
            simgr.stashes[stash] = prioritized_states[:15]
            simgr.stashes['tainted_high_priority'].extend(high_priority[5:] if len(high_priority) > 5 else [])
            simgr.stashes['tainted_medium_priority'].extend(prioritized_states[15:])
        
        if self.logger:
            self.logger.debug(f"State prioritization: {len(high_priority)} high, "
                             f"{len(medium_priority)} medium, {len(normal_priority)} normal priority")
            self.logger.debug(f"Active states after prioritization: {len(simgr.stashes[stash])}")
    
    def _calculate_comprehensive_taint_score(self, state):
        """
        Calculate a comprehensive taint relevance score for a given state.
        """
        score = 0.0
        
        try:
            # 1. Base score from existing taint_score mechanism
            base_score = state.globals.get("taint_score", 0)
            score += base_score
            
            # 2. FIXED: Give all states a minimum exploration score
            score += 1.0  # Base exploration score so states don't get stuck
            
            # 3. Check if current function is tainted
            current_func = self._get_current_function_name(state)
            if current_func and self.project and hasattr(self.project, 'tainted_functions'):
                if current_func in self.project.tainted_functions:
                    score += 6.0
                    if self.logger:
                        self.logger.debug(f"State in tainted function {current_func}, +6.0 score")
            
            # 4. Check for tainted registers
            tainted_regs = self._check_tainted_registers(state)
            score += len(tainted_regs) * 2.0
            
            # 5. Check for tainted memory access
            if self.project and hasattr(self.project, 'tainted_memory_regions'):
                memory_score = self._check_tainted_memory_access(state)
                score += memory_score * 3.0
            
            # 6. Proximity to input functions
            if self._recently_called_input_function(state):
                score += 5.0
            
            # 7. FIXED: Less aggressive depth penalty
            depth = len(state.history.bbl_addrs) if state.history.bbl_addrs else 0
            if depth > 200:
                score *= 0.9  # Small penalty
            elif depth > 400:
                score *= 0.8  # Moderate penalty
            
            # 8. Bonus for new tainted edges potential
            edge_potential = self._calculate_edge_potential(state)
            score += edge_potential
            
            # 9. FIXED: Bonus for main function and entry points
            if current_func and ('main' in current_func.lower() or state.addr == getattr(self.project, 'entry', 0)):
                score += 2.0
            
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Error calculating taint score: {e}")
            score = 1.0  # Default exploration score instead of 0.1
        
        return max(score, 1.0)  # Ensure minimum exploration score
    
    def _get_current_function_name(self, state):
        """Get the name of the current function."""
        try:
            if self.project and hasattr(self.project, 'kb') and self.project.kb.functions:
                func = self.project.kb.functions.get_by_addr(state.addr)
                if func and func.name:
                    return func.name
            return f"sub_{state.addr:#x}"
        except:
            return None
    
    def _check_tainted_registers(self, state):
        """Check for tainted data in registers."""
        tainted_regs = []
        try:
            if self.project and hasattr(self.project, 'arch_info'):
                arg_regs = self.project.arch_info.get('argument_registers', [])
                for reg_name in arg_regs[:3]:  # Check first 3 argument registers
                    try:
                        reg_value = getattr(state.regs, reg_name)
                        if hasattr(reg_value, 'symbolic') and reg_value.symbolic:
                            if hasattr(reg_value, 'variables'):
                                for var_name in reg_value.variables:
                                    if 'taint_source_' in str(var_name):
                                        tainted_regs.append(reg_name)
                                        break
                    except:
                        continue
        except:
            pass
        return tainted_regs
    
    def _check_tainted_memory_access(self, state):
        """Check if state accesses tainted memory regions."""
        try:
            access_count = 0
            current_addr = state.addr
            
            for region_addr, region_size in self.project.tainted_memory_regions.items():
                if region_addr <= current_addr < region_addr + region_size:
                    access_count += 1
            
            return access_count
        except:
            return 0
    
    def _recently_called_input_function(self, state):
        """Check if state recently called an input function."""
        try:
            input_functions = {'fgets', 'gets', 'scanf', 'read', 'recv', 'fread'}
            if hasattr(state.history, 'recent_bbl_addrs') and state.history.recent_bbl_addrs:
                recent_blocks = state.history.recent_bbl_addrs[-5:]
                for addr in recent_blocks:
                    if self.project and hasattr(self.project, 'kb'):
                        func = self.project.kb.functions.get_by_addr(addr)
                        if func and func.name in input_functions:
                            return True
            return False
        except:
            return False
    
    def _calculate_edge_potential(self, state):
        """Calculate potential for discovering new tainted edges."""
        try:
            current_func = self._get_current_function_name(state)
            if not current_func or not self.project:
                return 0.0
            
            # Bonus if this function hasn't been seen as tainted yet
            if hasattr(self.project, 'tainted_functions'):
                if current_func not in self.project.tainted_functions:
                    return 2.0
            
            return 0.0
        except:
            return 0.0
    
    def _post_step_processing(self, simgr):
        """Process states after stepping."""
        # Move high-priority states back to active if active is getting low
        if len(simgr.active) < 3 and simgr.stashes.get('tainted_high_priority'):
            num_to_move = min(3, len(simgr.stashes['tainted_high_priority']))
            moving_states = simgr.stashes['tainted_high_priority'][:num_to_move]
            simgr.stashes['tainted_high_priority'] = simgr.stashes['tainted_high_priority'][num_to_move:]
            simgr.active.extend(moving_states)
            
            if self.logger:
                self.logger.debug(f"Moved {num_to_move} high-priority states back to active")
    
    def _update_metrics(self, simgr):
        """Update exploration metrics."""
        for state in simgr.deadended + simgr.stashes.get('found', []):
            state_id = id(state)
            if state_id in self.state_scores:
                if self.state_scores[state_id] >= 4.0:
                    self.tainted_states_explored += 1
                else:
                    self.untainted_states_explored += 1
    
    def get_exploration_metrics(self):
        """Get current exploration metrics."""
        elapsed_time = time.time() - self.exploration_start_time
        total_states = self.tainted_states_explored + self.untainted_states_explored
        
        return {
            'elapsed_time': elapsed_time,
            'total_states_explored': total_states,
            'tainted_states_explored': self.tainted_states_explored,
            'untainted_states_explored': self.untainted_states_explored,
            'taint_exploration_ratio': (
                self.tainted_states_explored / max(total_states, 1)
            )
        }
    
    def print_metrics(self):
        """Print exploration metrics."""
        metrics = self.get_exploration_metrics()
        if self.logger:
            self.logger.info("="*50)
            self.logger.info("TAINT-GUIDED EXPLORATION METRICS")
            self.logger.info("="*50)
            self.logger.info(f"Exploration Time: {metrics['elapsed_time']:.2f}s")
            self.logger.info(f"Total States Explored: {metrics['total_states_explored']}")
            self.logger.info(f"Tainted States: {metrics['tainted_states_explored']}")
            self.logger.info(f"Untainted States: {metrics['untainted_states_explored']}")
            self.logger.info(f"Taint Ratio: {metrics['taint_exploration_ratio']:.2%}")
            self.logger.info("="*50)
