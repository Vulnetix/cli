class Service:
    ~>async def update(
        self,
        user_id,
        payload,
        admin=False,
    ):
        """Update a user record.

        Args:
            user_id: primary key
            payload: fields to change
        """
        return await self.db.save(user_id, payload, admin)
