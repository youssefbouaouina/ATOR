"""Offline ML assets for the ATOR DFIR framework (Layer 4.5 ML).

This package holds *offline* concerns only: third-party corpus ingestion,
model training entry points and the evaluation harness. Nothing here is
imported by the FastAPI server at request time - production inference lives
in ``server.engine.ml_*`` so the server never depends on training code.
"""
