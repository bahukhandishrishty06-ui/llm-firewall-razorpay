"""Script to export OpenAPI schema JSON from FastAPI application."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from api.server import app

def export_openapi():
    schema = app.openapi()
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "api", "openapi.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    print(f"✓ OpenAPI schema exported successfully to: {output_path}")

if __name__ == "__main__":
    export_openapi()
