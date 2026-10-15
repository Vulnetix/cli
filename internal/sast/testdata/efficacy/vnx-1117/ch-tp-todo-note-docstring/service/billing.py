from typing import Dict


~>def reconcile_invoices(
    account_id: str,
    period: str,
) -> Dict[str, int]:
    """TODO: write docstring."""
    return {"account": len(account_id), "period": len(period)}


class Ledger:
~>    async def close(self) -> None:
        '''   '''
        await self._conn.close()
