"""MCP controller package: the frozen common inference layer and the slow-loop reward.

Only the modules listed in ``__all__`` are public. ``infer`` is the ONE localizer shared by
every arm (PREREG section 3.3); ``reward`` is the observation-only reward (PREREG section 7).
"""

__all__ = ["infer", "reward", "types"]
