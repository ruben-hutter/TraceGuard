# TraceGuard: Optimizing Symbolic Execution Through Taint Analysis

## Bachelor Thesis Presentation Structure (30 minutes + Q&A)

### Agenda

1. **The Challenge:** Software vulnerabilities and current detection limits
2. **The Problem:** Why symbolic execution struggles (5 min)
    - "Step back" -> where are vulnerabilities and problems in programs?
        - In input
    - Big picture and also more specific challenges
    - Compare also to Fuzzing
3. **The Insight:** Taint-guided exploration concept (5 min)
4. **The Solution:** TraceGuard approach (6 min)
5. **The Results:** Evaluation & impact (6 min)
6. **Live Demo:** TraceGuard in action (4 min)
7. **Future Directions** (3 min)
8. **Summary and conclusion** (1 min)
    - In welchem Kontext man es einsetzten könnte

---

## Slide 2: Where Do Software Vulnerabilities Actually Hide?
- Start with security fundamentals: "Where do we actually find bugs?"
- Point to diagram: Data flow from external sources inward
- Emphasize: Risk concentrated at input boundaries
- **Key point**: Not all code equally vulnerable - follow the data

## Slide 3: Common Vulnerability Patterns
- Give concrete examples of input-related bugs
- Walk through attack flow diagram: Input → Parse → Memory → Exploit
- Emphasize the pattern: malicious input flowing through insufficient checks
- **Setup**: "This shows us we need to follow data flow to find vulnerabilities"

## Slide 4: The Challenge: Finding These Vulnerabilities
- Traditional methods miss the important cases
- Point to diagram: Testing hits normal inputs, sometimes edge cases
- **Critical gap**: Malicious inputs (where vulnerabilities hide) are missed
- **Transition**: "We need automated approaches that can find these hidden cases"

## Slide 5: Symbolic Execution - The Promise
- Introduce SE as a solution to the testing gap
- Mathematical approach vs concrete values
- **Key advantage**: Systematic exploration can reach complex conditions
- **Promise**: "This should solve our problem of missing hidden vulnerabilities"

## Slide 6: The Reality - Path Explosion Problem
- Show the mathematical reality: exponential growth
- Point to figure: 3 conditions manageable, 20 conditions impossible
- **Reality check**: Real programs have thousands of conditions
- **Problem**: "The systematic approach becomes computationally impossible"

## Slide 7: Comparing Approaches
- **Now introduce fuzzing** as the other main automated approach
- Show the trade-offs: Fast vs systematic
- **Setup for solution**: "We need SE's systematic power with better efficiency"
- **Bridge**: "What if we could guide SE to focus on the right paths?"

---

Here are speaking notes for "The Insight" section:

## Slide 8: The Core Insight - Taint as a Guide
- **Connect to previous**: "We saw SE has power but wastes resources. What if we could guide it?"
- **Point to left diagram**: Classical SE explores all paths equally - no prioritization
- **Point to right diagram**: Taint-guided follows the red (dangerous) data paths
- **Key realization**: "Not all paths are equal - paths with user data are more likely to have bugs"
- **Transition**: "But how do we track this user data? That's where taint analysis comes in."

## Slide 9: What is Taint Analysis?
- **Define**: "Taint analysis tracks untrusted data as it flows through the program"
- **Walk through diagram**: 
  - Source: "Data enters from fgets()"
  - Propagation: "Flows through process_data()"
  - Sink: "Reaches strcpy() - potential vulnerability"
- **Code example**: "Here's what this looks like in real code"
- **Key insight**: "This gives us a roadmap - follow the tainted data to find bugs"

## Slide 10: Traditional Approach vs. TraceGuard
- **Left side**: "Traditional SE explores everything hoping to find bugs"
- **Right side**: "TraceGuard uses real-time taint tracking to prioritize"
- **Key difference**: "Integration, not post-processing - we guide SE as it runs"
- **Result preview**: "In our hardest test, this found 5x more vulnerabilities while exploring only 37% of the code"
- **Transition**: "So how exactly does this work? Let me show you the solution..."

---

The slides look good overall! Here are speaking notes and one small improvement suggestion:

## Slide 11: TraceGuard Architecture - Overview
- **Big picture**: "Here's how TraceGuard works - three phases that work together"
- **Phase 1**: "Static analysis builds the foundation - find all functions, create hooks"
- **Phase 2**: "Dynamic taint tracking during execution - follow the data in real-time"  
- **Phase 3**: "Guided symbolic execution - prioritize states based on taint information"
- **Integration**: "Built on top of Angr framework - extends rather than replaces"
- **Transition**: "Let me show you the key technical details..."

## Slide 12: How TraceGuard Works - Function Hooking
- **Core mechanism**: "Function hooking is how we detect and track taint"
- **Input hooks** (red): "When fgets/scanf called - mark data as tainted"
- **Generic hooks** (blue): "All other functions - check if they receive tainted data"
- **Real-time analysis**: "Examine registers and memory during execution"
- **Example**: "fgets() creates 'taint_source_fgets_001' - unique identifier"
- **Key point**: "This happens during symbolic execution, not before or after"

## Slide 13: Dynamic State Scoring Algorithm  
- **Every state gets scored**: "Based on how much it interacts with tainted data"
- **Walk through diagram**: State → Check taint → Classify → Queue
- **Scoring details**: "+20 for input functions, +3 for tainted functions, penalties for depth"
- **Three tiers**: "High (≥6.0), Medium (≥2.0), Normal (<2.0)"
- **Result**: "States with more taint interaction get explored first"

## Slide 14: Exploration Strategy
- **Bounded approach**: "Maximum 15 active states prevents path explosion"
- **Priority ordering**: "High → Medium → Normal priority"
- **Dynamic replacement**: "New high-priority states can bump out low-priority ones"
- **Overflow management**: "Excess states stored in reserves, can be recovered later"
- **Key advantage**: "Maintains focus on security-relevant paths while preventing resource exhaustion"

---

## Slide 15: Evaluation Methodology
- Start: "Before diving into results, let's quickly recap how we evaluated TraceGuard."
- Test Suite Design: "We used 7 synthetic programs, specifically designed to challenge symbolic execution."
- Key aspects: "These programs included simple baselines, but also cases with conditional explosions, deep exploration, multi-function calls, recursive calls, and most importantly, a state explosion stress test."
- Controlled Comparison: "The crucial part was a direct, controlled comparison between TraceGuard and the classical Angr symbolic execution strategy."
- Purpose: "This setup allowed us to directly measure TraceGuard's impact on performance and vulnerability detection."

## Slide 16: Key Results - Execution Time Performance (Graph Slide)
- Start: "Let's begin with execution time performance."
- Point to graph: "As you can see from this grouped bar chart, the execution times for TraceGuard (blue) and Classical Angr (orange) are generally quite similar across most test programs."
- Acknowledge `test_state_explosion`: "Even for the challenging 'state explosion' test, while times are higher for both, the difference between TraceGuard and Classical remains relatively small."
- Transition: "This is a positive first indicator, suggesting our approach doesn't introduce significant overhead. But the real story is in what these similar times yielded..."

## Slide 17: Key Results - Execution Time Performance (Insights Slide)
- Recap: "So, looking at the numbers more closely, our execution time performance was indeed competitive."
- Detail 1: "We saw very little variation, ranging from a slight 5.3% slower to an 8.5% faster performance for TraceGuard."
- Detail 2 (Crucial Link): "Specifically for the state explosion case, TraceGuard's time was comparable to Classical, but this comparable time achieved something truly remarkable – it found 5 times more vulnerabilities."
- Detail 3: "And for complex branching scenarios, like the 'conditional explosion' test, TraceGuard even showed an 8.5% improvement in speed."
- Summary: "This means we can maintain efficiency, and sometimes even improve it, while gaining significant advantages in detection."

## Slide 18: Vulnerability Detection Effectiveness (Graph Slide)
- Start: "Now, let's look at the effectiveness: how many vulnerabilities did each strategy find?"
- Point to graph: "For most of our synthetic programs, both TraceGuard (blue) and Classical Angr (orange) successfully detected 1 vulnerability, achieving 100% detection on those specific tests."
- Dramatic highlight `test_state_explosion`: "However, observe the striking difference for the 'test_state_explosion' program. Here, TraceGuard found 5 vulnerabilities, while Classical Angr found only 1!"
- Impact: "This graph visually demonstrates the power of our taint-guided approach in highly complex and challenging scenarios."
- Transition: "Let's quantify this a bit more..."

## Slide 19: Vulnerability Detection Effectiveness (Insights Slide)
- Confirm Detection: "Across the board, TraceGuard achieved 100% vulnerability detection for all test programs."
- Reiterate Key Success: "Crucially, in the challenging 'state explosion' scenario, TraceGuard found a remarkable 5 times more vulnerabilities than the classical approach."
- Reinforce Reliability: "This consistent performance across diverse program types underscores TraceGuard's reliability and superior capability in complex, security-critical contexts."
- Bridge to next section: "This raises an important question: how did TraceGuard find more bugs without taking significantly more time, and sometimes even less?"

## Slide 20: Coverage vs. Effectiveness (Graph Slide)
- Start: "This brings us to the core of our approach: the relationship between code coverage and actual vulnerability detection."
- Point to graph: "This graph shows TraceGuard's 'Efficiency Ratio' – essentially, how much coverage TraceGuard needed compared to Classical Angr to achieve its results. A lower percentage here means higher efficiency for TraceGuard."
- Highlight low ratio: "Notice the particularly low ratio for 'test_state_explosion' – indicating TraceGuard achieved its superior results by exploring a much smaller *proportion* of the code that Classical Angr explored."
- Core message hint: "This challenges the traditional belief that more coverage always equals better bug finding."
- Transition: "Let's unpack this 'Paradigm Shift' in more detail."

## Slide 21: Coverage vs. Effectiveness (Paradigm Shift Slide)
- Traditional View: "Traditionally, the metric for symbolic execution has been: more code coverage leads to a better analysis and more bugs found."
- Our Finding: "However, our research shows a paradigm shift: focused exploration, guided by taint information, is what truly leads to more vulnerabilities."
- Concrete Example: "For our 'test_state_explosion' program, TraceGuard found 5 times more vulnerabilities, while only needing to cover approximately 37% of the code covered by Classical Angr to do so."
- Powerful Conclusion: "This clearly demonstrates that the **quality of exploration matters more than quantity**."

---

TODO: Future Directions, Conclusion
