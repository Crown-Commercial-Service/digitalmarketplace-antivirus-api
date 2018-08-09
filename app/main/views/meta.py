from flask import jsonify

from app.main import main


@main.route('/')
def root():
    """Entry point for the API, show the resources that are available."""
    return (
        jsonify({
            "this": "is a pointless view that exists to appease the gods of REST",
        }),
        200,
    )
