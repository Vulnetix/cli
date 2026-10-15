class Gateway:
    def charge(self, card, amount):
        """Charge a card.

        Args:
            card: card token
            amount: cents
        """
        raise NotImplementedError

    def capture(self, txn):
        """Capture a payment.

        Args:
            txn: the authorised transaction
        """
        try:
            return self._capture(txn)
        except Exception:
            log.exception("capture failed")
            raise

    def batch(self, txns):
        """Capture several payments.

        Args:
            txns: transactions
        """
        def one(t):
            if t is None:
                raise ValueError("empty")
            return self.capture(t)
        return [one(t) for t in txns]
