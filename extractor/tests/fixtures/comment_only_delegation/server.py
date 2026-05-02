"""A server that only mentions 'Client' in a docstring/comment — must NOT trigger delegation."""

# This server is for the MCP Client to call. It does not delegate.
# References ClientSession in this comment but does not actually import it.

def hello():
    """Returns a greeting. Used by the MCP Client."""
    return "hello"
