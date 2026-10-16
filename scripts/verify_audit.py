"""CLI tool to verify audit chain integrity."""

import asyncio
from backend.services.audit_service import audit_service


async def main():
    await audit_service.initialize()
    result = audit_service.verify_chain()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    import json
    asyncio.run(main())